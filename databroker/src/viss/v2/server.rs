/********************************************************************************
* Copyright (c) 2023 Contributors to the Eclipse Foundation
*
* See the NOTICE file(s) distributed with this work for additional
* information regarding copyright ownership.
*
* This program and the accompanying materials are made available under the
* terms of the Apache License 2.0 which is available at
* http://www.apache.org/licenses/LICENSE-2.0
*
* SPDX-License-Identifier: Apache-2.0
********************************************************************************/

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    pin::Pin,
    sync::Arc,
    time::SystemTime,
};

use futures::{
    stream::{self, AbortHandle, Abortable},
    Stream, StreamExt,
};
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    authorization::Authorization,
    broker::{self, AuthorizedAccess, UpdateError},
    glob::Matcher,
    permissions::{self, Permissions},
};

use super::{conversions, types::*};

#[tonic::async_trait]
pub(crate) trait Viss: Send + Sync + 'static {
    async fn get(&self, request: GetRequest) -> Result<GetSuccessResponse, GetErrorResponse>;
    async fn set(&self, request: SetRequest) -> Result<SetSuccessResponse, SetErrorResponse>;

    type SubscribeStream: Stream<Item = Result<SubscriptionEvent, SubscriptionErrorEvent>>
        + Send
        + 'static;

    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<(SubscribeSuccessResponse, Self::SubscribeStream), SubscribeErrorResponse>;

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequest,
    ) -> Result<UnsubscribeSuccessResponse, UnsubscribeErrorResponse>;
}

pub struct SubscriptionHandle {
    abort_handle: AbortHandle,
}

impl From<AbortHandle> for SubscriptionHandle {
    fn from(abort_handle: AbortHandle) -> Self {
        Self { abort_handle }
    }
}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

pub struct Server {
    broker: broker::DataBroker,
    authorization: Authorization,
    subscriptions: Arc<RwLock<HashMap<SubscriptionId, SubscriptionHandle>>>,
}

impl Server {
    pub fn new(broker: broker::DataBroker, authorization: Authorization) -> Self {
        Self {
            broker,
            authorization,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl Viss for Server {
    async fn get(&self, request: GetRequest) -> Result<GetSuccessResponse, GetErrorResponse> {
        let request_id = request.request_id;

        if let Some(Filter::StaticMetadata(_)) = &request.filter {
            // Authorization not required for metadata, don't bail if an
            // access token is missing.
            let broker = self.broker.authorized_access(&permissions::ALLOW_NONE);
            let metadata = generate_metadata(&broker, request.path.as_ref()).await;
            return Ok(GetSuccessResponse::Metadata(MetadataResponse {
                request_id,
                metadata,
            }));
        } else if let Some(Filter::History(history_filter)) = &request.filter {
            // History filter: validate the ISO 8601 duration parameter and return
            // a deterministic error. Full history persistence is not yet available,
            // so valid requests receive a 501 Not Implemented response.
            if !is_valid_iso8601_duration(&history_filter.parameter) {
                return Err(GetErrorResponse {
                    request_id,
                    ts: SystemTime::now().into(),
                    error: Error::BadRequest {
                        msg: Some("Time duration is invalid.".into()),
                    },
                });
            }
            return Err(GetErrorResponse {
                request_id,
                ts: SystemTime::now().into(),
                error: Error::NotImplemented,
            });
        } else if let Some(Filter::DynamicMetadata(filter)) = &request.filter {
            // Handle dynamic metadata requests
            if filter
                .parameter
                .contains(&"server_capabilities".to_string())
            {
                // Return server capabilities
                return Ok(GetSuccessResponse::ServerCapabilities(
                    ServerCapabilitiesResponse {
                        filter: vec![
                            "timebased".to_string(),
                            "change".to_string(),
                            "dynamic_metadata".to_string(),
                        ],
                        transport_protocol: vec!["https".to_string(), "wss".to_string()],
                    },
                ));
            } else if filter.parameter.contains(&"availability".to_string()) {
                // Handle availability filter - return all available data points
                let broker = self.broker.authorized_access(&permissions::ALLOW_NONE);
                let mut entries_data = Vec::new();

                broker
                    .for_each_entry(|entry| {
                        let entry_path = &entry.metadata().path;

                        // Check if entry path starts with the requested path
                        if entry_path.starts_with(request.path.as_ref()) {
                            if let Ok(datapoint) = entry.datapoint() {
                                let dp = DataPoint::from(datapoint.clone());
                                entries_data.push(DataObject {
                                    path: Path::from(entry_path.clone()),
                                    dp,
                                });
                            }
                        }
                    })
                    .await;

                return Ok(GetSuccessResponse::Data(DataResponse {
                    request_id,
                    data: Data::Array(entries_data),
                }));
            } else {
                // Unsupported dynamic metadata parameter
                return Err(GetErrorResponse {
                    request_id,
                    ts: SystemTime::now().into(),
                    error: Error::NotImplemented,
                });
            }
        } else if let Some(Filter::Paths(paths_filter)) = &request.filter {
            let request_path = request.path.as_ref();
            if request_path.contains('*') {
                return Err(GetErrorResponse {
                    request_id,
                    ts: SystemTime::now().into(),
                    error: Error::NotFoundInvalidPath,
                });
            }

            let permissions = resolve_permissions(&self.authorization, &request.authorization)
                .map_err(|error| GetErrorResponse {
                    request_id: request_id.clone(),
                    error,
                    ts: SystemTime::now().into(),
                })?;
            let broker = self.broker.authorized_access(&permissions);

            let mut request_matcher: Vec<(Matcher, bool)> = Vec::new();
            let mut entries_data = Vec::new();
            let mut signal_errors = Vec::new();

            for path in &paths_filter.parameter {
                let new_path = format!("{request_path}.{path}");
                if let Ok(matcher) = Matcher::new(&new_path) {
                    request_matcher.push((matcher, false));
                }
            }

            if !request_matcher.is_empty() {
                for (matcher, is_match) in &mut request_matcher {
                    broker
                        .for_each_entry(|entry| {
                            let glob_path = &entry.metadata().glob_path;
                            let path = entry.metadata().path.clone();
                            if matcher.is_match(glob_path) {
                                match entry.datapoint() {
                                    Ok(datapoint) => {
                                        let dp = DataPoint::from(datapoint.clone());
                                        *is_match = true;
                                        entries_data.push(DataObject {
                                            path: Path::from(path),
                                            dp,
                                        });
                                    }
                                    Err(_) => {
                                        signal_errors.push(path);
                                    }
                                }
                            }
                        })
                        .await;

                    // Not found any matches meaning it could be a branch path request
                    // Only support branches like Vehicle.Cabin.Sunroof but not like **.Sunroof
                    if !matcher.as_string().starts_with("**")
                        && !matcher.as_string().ends_with("/**")
                        && !(*is_match)
                    {
                        if let Ok(branch_matcher) = Matcher::new(&(matcher.as_string() + "/**")) {
                            broker
                                .for_each_entry(|entry| {
                                    let glob_path = &entry.metadata().glob_path;
                                    let path = entry.metadata().path.clone();
                                    if branch_matcher.is_match(glob_path) {
                                        match entry.datapoint() {
                                            Ok(datapoint) => {
                                                let dp = DataPoint::from(datapoint.clone());
                                                *is_match = true;
                                                entries_data.push(DataObject {
                                                    path: Path::from(path),
                                                    dp,
                                                });
                                            }
                                            Err(_) => {
                                                signal_errors.push(path);
                                            }
                                        }
                                    }
                                })
                                .await;
                        }
                    }
                }
            }

            // https://w3c.github.io/automotive/spec/VISSv2_Core.html#error-handling
            if signal_errors.is_empty() {
                Ok(GetSuccessResponse::Data(DataResponse {
                    request_id,
                    data: Data::Array(entries_data),
                }))
            } else {
                Err(GetErrorResponse {
                    request_id,
                    ts: SystemTime::now().into(),
                    error: Error::Forbidden {
                        msg: Some(format!(
                            "Permission denied for some signal: {}",
                            signal_errors.join(", ")
                        )),
                    },
                })
            }
        } else {
            let permissions = resolve_permissions(&self.authorization, &request.authorization)
                .map_err(|error| GetErrorResponse {
                    request_id: request_id.clone(),
                    error,
                    ts: SystemTime::now().into(),
                })?;
            let broker = self.broker.authorized_access(&permissions);

            // Get datapoints
            match broker.get_datapoint_by_path(request.path.as_ref()).await {
                Ok(datapoint) => {
                    let dp = DataPoint::from(datapoint);
                    Ok(GetSuccessResponse::Data(DataResponse {
                        request_id,
                        data: Data::Object(DataObject {
                            path: request.path,
                            dp,
                        }),
                    }))
                }
                Err(err) => Err(GetErrorResponse {
                    request_id,
                    ts: SystemTime::now().into(),
                    error: match err {
                        broker::ReadError::NotFound => Error::NotFoundInvalidPath,
                        broker::ReadError::PermissionDenied => Error::Forbidden { msg: None },
                        broker::ReadError::PermissionExpired => Error::UnauthorizedTokenExpired,
                    },
                }),
            }
        }
    }

    async fn set(&self, request: SetRequest) -> Result<SetSuccessResponse, SetErrorResponse> {
        let request_id = request.request_id;
        let permissions = resolve_permissions(&self.authorization, &request.authorization)
            .map_err(|error| SetErrorResponse {
                request_id: request_id.clone(),
                error,
                ts: SystemTime::now().into(),
            })?;
        let broker = self.broker.authorized_access(&permissions);

        match broker.get_metadata_by_path(request.path.as_ref()).await {
            Some(metadata) => {
                if metadata.entry_type != broker::EntryType::Actuator {
                    return Err(SetErrorResponse {
                        request_id,
                        error: Error::UnauthorizedReadOnly,
                        ts: SystemTime::now().into(),
                    });
                }

                let value = request.value;

                let update = value
                    .try_into_type(&metadata.data_type)
                    .map(|actuator_target| broker::EntryUpdate {
                        path: None,
                        datapoint: None,
                        actuator_target: Some(Some(broker::Datapoint {
                            value: actuator_target,
                            source_ts: None,
                            ts: SystemTime::now(),
                        })),
                        entry_type: None,
                        data_type: None,
                        description: None,
                        min: None,
                        max: None,
                        allowed: None,
                        unit: None,
                    })
                    .map_err(|err| SetErrorResponse {
                        request_id: request_id.clone(),
                        error: match err {
                            conversions::Error::ParseError => Error::BadRequest {
                                msg: Some(format!(
                                    "Failed to parse the value as a {}",
                                    DataType::from(metadata.data_type.clone())
                                )),
                            },
                        },
                        ts: SystemTime::now().into(),
                    })?;

                let updates = vec![(metadata.id, update)];
                match broker.update_entries(updates).await {
                    Ok(()) => Ok(SetSuccessResponse {
                        request_id,
                        ts: SystemTime::now().into(),
                    }),
                    Err(errors) => {
                        let error = if let Some((_, error)) = errors.first() {
                            match error {
                                UpdateError::NotFound => Error::NotFoundInvalidPath,
                                UpdateError::WrongType => Error::BadRequest {
                                    msg: Some("Wrong data type.".into()),
                                },
                                UpdateError::OutOfBoundsAllowed => Error::BadRequest {
                                    msg: Some("Value out of allowed bounds.".into()),
                                },
                                UpdateError::OutOfBoundsMinMax => Error::BadRequest {
                                    msg: Some("Value out of min/max bounds.".into()),
                                },
                                UpdateError::OutOfBoundsType => Error::BadRequest {
                                    msg: Some("Value out of type bounds.".into()),
                                },
                                UpdateError::UnsupportedType => Error::BadRequest {
                                    msg: Some("Unsupported data type.".into()),
                                },
                                UpdateError::PermissionDenied => Error::Forbidden { msg: None },
                                UpdateError::PermissionExpired => Error::UnauthorizedTokenExpired,
                            }
                        } else {
                            Error::InternalServerError
                        };

                        Err(SetErrorResponse {
                            request_id,
                            error,
                            ts: SystemTime::now().into(),
                        })
                    }
                }
            }
            None => {
                // Not found
                Err(SetErrorResponse {
                    request_id,
                    error: Error::NotFoundInvalidPath,
                    ts: SystemTime::now().into(),
                })
            }
        }
    }

    type SubscribeStream = Pin<
        Box<
            dyn Stream<Item = Result<SubscriptionEvent, SubscriptionErrorEvent>>
                + Send
                + Sync
                + 'static,
        >,
    >;

    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<(SubscribeSuccessResponse, Self::SubscribeStream), SubscribeErrorResponse> {
        let request_id = request.request_id;
        if let Some(Filter::Curvelog(_)) = &request.filter {
            return Err(SubscribeErrorResponse {
                request_id,
                error: Error::NotImplemented,
                ts: SystemTime::now().into(),
            });
        }

        let permissions = resolve_permissions(&self.authorization, &request.authorization)
            .map_err(|error| SubscribeErrorResponse {
                request_id: request_id.clone(),
                error,
                ts: SystemTime::now().into(),
            })?;
        let broker = self.broker.authorized_access(&permissions);

        let Some(entries) = broker
            .get_id_by_path(request.path.as_ref())
            .await
            .map(|id| HashMap::from([(id, HashSet::from([broker::Field::Datapoint]))]))
        else {
            return Err(SubscribeErrorResponse {
                request_id,
                error: Error::NotFoundInvalidPath,
                ts: SystemTime::now().into(),
            });
        };

        let interval_ms = if let Some(Filter::Timebased(timebased)) = &request.filter {
            Some(timebased.parameter.period)
        } else {
            None
        };
        let filter_state = request
            .filter
            .as_ref()
            .and_then(SubscriptionFilterState::from);

        match broker.subscribe(entries, None, interval_ms).await {
            Ok(stream) => {
                let subscription_id = SubscriptionId::new();

                let (abort_handle, abort_registration) = AbortHandle::new_pair();

                // Make the stream abortable
                let stream = Abortable::new(stream, abort_registration);

                // Register abort handle
                self.subscriptions.write().await.insert(
                    subscription_id.clone(),
                    SubscriptionHandle::from(abort_handle),
                );

                let stream = convert_to_viss_stream(subscription_id.clone(), stream, filter_state);

                Ok((
                    SubscribeSuccessResponse {
                        request_id,
                        subscription_id,
                        ts: SystemTime::now().into(),
                    },
                    Box::pin(stream),
                ))
            }
            Err(err) => Err(SubscribeErrorResponse {
                request_id,
                error: match err {
                    broker::SubscriptionError::NotFound => Error::NotFoundInvalidPath,
                    broker::SubscriptionError::InvalidInput => Error::NotFoundInvalidPath,
                    broker::SubscriptionError::InternalError => Error::InternalServerError,
                    broker::SubscriptionError::InvalidBufferSize => Error::InternalServerError,
                },
                ts: SystemTime::now().into(),
            }),
        }
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequest,
    ) -> Result<UnsubscribeSuccessResponse, UnsubscribeErrorResponse> {
        let subscription_id = request.subscription_id;
        let request_id = request.request_id;
        match self.subscriptions.write().await.remove(&subscription_id) {
            Some(_) => {
                // Stream is aborted when handle is dropped
                Ok(UnsubscribeSuccessResponse {
                    request_id,
                    subscription_id,
                    ts: SystemTime::now().into(),
                })
            }
            None => Err(UnsubscribeErrorResponse {
                request_id,
                subscription_id,
                error: Error::NotFoundInvalidSubscriptionId,
                ts: SystemTime::now().into(),
            }),
        }
    }
}

fn convert_to_viss_stream(
    subscription_id: SubscriptionId,
    stream: impl Stream<Item = Option<broker::EntryUpdates>>,
    mut filter_state: Option<SubscriptionFilterState>,
) -> impl Stream<Item = Result<SubscriptionEvent, SubscriptionErrorEvent>> {
    stream.flat_map(move |item| {
        let subscription_id = subscription_id.clone();
        let batch_ts = SystemTime::now();
        match item {
            Some(value) => {
                let events: Vec<Result<SubscriptionEvent, SubscriptionErrorEvent>> = value
                    .updates
                    .into_iter()
                    .filter_map(
                        |update| match (update.update.path, update.update.datapoint) {
                            (Some(path), Some(datapoint)) => {
                                if let Some(state) = &mut filter_state {
                                    if !state.matches(&datapoint) {
                                        return None;
                                    }
                                }
                                Some(Ok(SubscriptionEvent {
                                    subscription_id: subscription_id.clone(),
                                    data: Data::Object(DataObject {
                                        path: path.into(),
                                        dp: datapoint.into(),
                                    }),
                                    ts: batch_ts.into(),
                                }))
                            }
                            (_, _) => Some(Err(SubscriptionErrorEvent {
                                subscription_id: subscription_id.clone(),
                                error: Error::InternalServerError,
                                ts: batch_ts.into(),
                            })),
                        },
                    )
                    .collect();
                stream::iter(events)
            }
            // if None, it means the provider is not available, meaning we should return the VISS error service_unavailable
            None => stream::iter(vec![Err(SubscriptionErrorEvent {
                subscription_id,
                error: Error::ServiceUnavailable,
                ts: batch_ts.into(),
            })]),
        }
    })
}

enum SubscriptionFilterState {
    Range(RangeFilter),
    Change(ChangeFilterState),
}

impl SubscriptionFilterState {
    fn from(filter: &Filter) -> Option<Self> {
        match filter {
            Filter::Range(range_filter) => Some(Self::Range(range_filter.clone())),
            Filter::Change(change_filter) => {
                Some(Self::Change(ChangeFilterState::new(change_filter.clone())))
            }
            _ => None,
        }
    }

    fn matches(&mut self, datapoint: &broker::Datapoint) -> bool {
        match self {
            SubscriptionFilterState::Range(range_filter) => {
                evaluate_range_filter(range_filter, datapoint)
            }
            SubscriptionFilterState::Change(change_filter) => change_filter.matches(datapoint),
        }
    }
}

struct ChangeFilterState {
    filter: ChangeFilter,
    last_emitted_value: Option<f64>,
}

impl ChangeFilterState {
    fn new(filter: ChangeFilter) -> Self {
        Self {
            filter,
            last_emitted_value: None,
        }
    }

    fn matches(&mut self, datapoint: &broker::Datapoint) -> bool {
        let Some(value) = datapoint_to_f64(datapoint) else {
            return false;
        };
        let Ok(diff_threshold) = self.filter.parameter.diff.parse::<f64>() else {
            return false;
        };

        let should_emit = if let Some(last_emitted) = self.last_emitted_value {
            evaluate_comparison_op(
                self.filter.parameter.logic_op.clone(),
                value - last_emitted,
                diff_threshold,
            )
        } else {
            true
        };

        if should_emit {
            self.last_emitted_value = Some(value);
        }

        should_emit
    }
}

fn evaluate_range_filter(filter: &RangeFilter, datapoint: &broker::Datapoint) -> bool {
    let Some(value) = datapoint_to_f64(datapoint) else {
        return false;
    };
    let Some(first_boundary) = filter.parameter.first() else {
        return false;
    };
    let Ok(first_threshold) = first_boundary.boundary.parse::<f64>() else {
        return false;
    };

    let mut result =
        evaluate_comparison_op(first_boundary.boundary_op.clone(), value, first_threshold);
    let mut previous_combination = first_boundary.combination_op.clone();

    for boundary in filter.parameter.iter().skip(1) {
        let Ok(threshold) = boundary.boundary.parse::<f64>() else {
            return false;
        };
        let current = evaluate_comparison_op(boundary.boundary_op.clone(), value, threshold);

        result = match previous_combination.unwrap_or(CombinationOp::And) {
            CombinationOp::And => result && current,
            CombinationOp::Or => result || current,
        };

        previous_combination = boundary.combination_op.clone();
    }

    result
}

fn evaluate_comparison_op(op: ComparisonOp, lhs: f64, rhs: f64) -> bool {
    const FLOAT_COMPARISON_EPSILON: f64 = 1e-9;

    match op {
        ComparisonOp::Gte => lhs >= rhs,
        ComparisonOp::Lte => lhs <= rhs,
        ComparisonOp::Gt => lhs > rhs,
        ComparisonOp::Lt => lhs < rhs,
        ComparisonOp::Eq => (lhs - rhs).abs() <= FLOAT_COMPARISON_EPSILON,
        ComparisonOp::Ne => (lhs - rhs).abs() > FLOAT_COMPARISON_EPSILON,
    }
}

fn datapoint_to_f64(datapoint: &broker::Datapoint) -> Option<f64> {
    match datapoint.value {
        broker::DataValue::Int32(value) => Some(value as f64),
        broker::DataValue::Int64(value) => Some(value as f64),
        broker::DataValue::Uint32(value) => Some(value as f64),
        broker::DataValue::Uint64(value) => Some(value as f64),
        broker::DataValue::Float(value) => Some(value as f64),
        broker::DataValue::Double(value) => Some(value),
        _ => None,
    }
}

fn resolve_permissions(
    authorization: &Authorization,
    token: &Option<String>,
) -> Result<Permissions, Error> {
    match authorization {
        Authorization::Disabled => Ok(permissions::ALLOW_ALL.clone()),
        Authorization::Enabled { token_decoder } => match token {
            Some(token) => match token_decoder.decode(token) {
                Ok(claims) => match Permissions::try_from(claims) {
                    Ok(permissions) => Ok(permissions),
                    Err(_) => Err(Error::UnauthorizedTokenInvalid),
                },
                Err(_) => Err(Error::UnauthorizedTokenInvalid),
            },
            None => Err(Error::UnauthorizedTokenMissing),
        },
    }
}

/// Validate that a string conforms to the ISO 8601 duration format.
///
/// Valid examples: "PT1H", "P1D", "P1Y2M3DT4H5M6S", "P1W"
/// Invalid examples: "INVALID", "1H", "", "PT"
fn is_valid_iso8601_duration(s: &str) -> bool {
    // Must start with 'P'
    let rest = match s.strip_prefix('P') {
        Some(r) => r,
        None => return false,
    };

    // An empty string after 'P' is invalid
    if rest.is_empty() {
        return false;
    }

    // Week format: P<n>W  (e.g. "P2W")
    if let Some(week_part) = rest.strip_suffix('W') {
        return !week_part.is_empty() && week_part.chars().all(|c| c.is_ascii_digit());
    }

    // Split date and time parts at 'T'
    let (date_part, time_part) = match rest.find('T') {
        Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
        None => (rest, None),
    };

    // Parse a sequence of <number><designator> tokens
    fn parse_designators(s: &str, valid: &[char]) -> bool {
        if s.is_empty() {
            return true;
        }
        let mut remaining = s;
        let mut found_any = false;
        while !remaining.is_empty() {
            // Consume digits
            let digit_end = remaining
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(remaining.len());
            if digit_end == 0 {
                return false; // designator found without preceding number
            }
            remaining = &remaining[digit_end..];
            // Consume designator
            match remaining.chars().next() {
                Some(d) if valid.contains(&d) => {
                    remaining = &remaining[1..];
                    found_any = true;
                }
                _ => return false,
            }
        }
        found_any
    }

    let date_ok = parse_designators(date_part, &['Y', 'M', 'D']);
    let time_ok = match time_part {
        Some(tp) => {
            // If 'T' is present the time part must not be empty
            if tp.is_empty() {
                false
            } else {
                parse_designators(tp, &['H', 'M', 'S'])
            }
        }
        None => true,
    };

    // At least one component (date or time) must be present
    let has_content = !date_part.is_empty() || time_part.is_some();
    date_ok && time_ok && has_content
}

async fn generate_metadata(
    db: &AuthorizedAccess<'_, '_>,
    path: &str,
) -> HashMap<String, MetadataEntry> {
    let mut metadata: HashMap<String, MetadataEntry> = HashMap::new();

    // We want to remove all but the last "component" present in the path.
    // For example, if requesting "Vehicle.Driver", we want to match
    // everything starting with "Vehicle.Driver" but include "Driver"
    // as the top level entry returned as metadata.
    let prefix_to_strip = match path.rsplit_once('.') {
        Some((prefix_excl_dot, _leaf)) => &path[..=prefix_excl_dot.len()],
        None => "",
    };

    // Include everything that starts with the requested path.
    // Insert into the metadata tree, with the top level being the last
    // "component" of the branch as described above.
    db.for_each_entry(|entry| {
        let entry_metadata = entry.metadata();
        let entry_path = &entry_metadata.path;
        if entry_path.starts_with(path) {
            if let Some(path) = entry_path.strip_prefix(prefix_to_strip) {
                insert_entry(&mut metadata, path, entry_metadata.into());
            }
        }
    })
    .await;

    metadata
}

fn insert_entry(entries: &mut HashMap<String, MetadataEntry>, path: &str, entry: MetadataEntry) {
    // Get the leftmost path component by splitting at '.'.
    // `split_once` will return None if there is only one component,
    // which means it's the leaf.
    match path.split_once('.') {
        Some((key, path)) => match entries.get_mut(key) {
            Some(MetadataEntry::Branch(branch_entry)) => {
                insert_entry(&mut branch_entry.children, path, entry);
            }
            Some(_) => {
                warn!("Should only be possible for branches to exist here");
                // ignore
            }
            None => {
                let mut branch = BranchEntry {
                    description: "".into(),
                    children: HashMap::default(),
                };
                insert_entry(&mut branch.children, path, entry);
                entries.insert(key.to_owned(), MetadataEntry::Branch(branch));
            }
        },
        None => {
            entries.insert(path.to_owned(), entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{
        ChangeNotification, DataValue, Datapoint, EntryUpdate, EntryUpdates, Field,
    };
    use futures::StreamExt;
    use std::collections::HashSet;
    use std::time::SystemTime;

    #[tokio::test]
    async fn subscribe_with_curvelog_filter_returns_not_implemented() {
        let broker = broker::DataBroker::new("test-version", "test-commit");
        let server = Server::new(broker, Authorization::Disabled);
        let request = serde_json::from_str::<SubscribeRequest>(
            r#"{
                "path":"Vehicle.Speed",
                "requestId":"curvelog-request",
                "filter":{
                    "type":"curvelog",
                    "parameter":{"maxerr":0.5,"bufsize":100}
                }
            }"#,
        )
        .expect("subscribe request should deserialize");

        let result = server.subscribe(request).await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!(
                "curvelog subscribe is deferred and should return a not_implemented error response"
            ),
        };

        let error_spec: ErrorSpec = error.error.into();
        assert_eq!(error_spec.number, 501);
        assert_eq!(error_spec.reason, "not_implemented");
    }
    fn make_notification(path: &str, value: i32) -> ChangeNotification {
        ChangeNotification {
            id: 1,
            update: EntryUpdate {
                path: Some(path.to_string()),
                datapoint: Some(Datapoint {
                    ts: SystemTime::now(),
                    source_ts: None,
                    value: DataValue::Int32(value),
                }),
                actuator_target: None,
                entry_type: None,
                data_type: None,
                description: None,
                allowed: None,
                min: None,
                max: None,
                unit: None,
            },
            fields: HashSet::from([Field::Datapoint]),
        }
    }

    fn datapoint(value: i32) -> broker::Datapoint {
        broker::Datapoint {
            ts: SystemTime::now(),
            source_ts: None,
            value: broker::DataValue::Int32(value),
        }
    }

    #[tokio::test]
    async fn test_convert_to_viss_stream_single_update() {
        let subscription_id = SubscriptionId::new();
        let entry_updates = EntryUpdates {
            updates: vec![make_notification("Vehicle.Speed", 100)],
        };
        let input = futures::stream::iter(vec![Some(entry_updates)]);
        let output: Vec<_> = convert_to_viss_stream(subscription_id, input, None)
            .collect()
            .await;
        assert_eq!(output.len(), 1);
        assert!(output[0].is_ok());
    }

    #[tokio::test]
    async fn test_convert_to_viss_stream_batch_emits_all_updates() {
        // Regression test: a batch with multiple updates must emit one event per update,
        // not just one (the original bug used `.pop()` and dropped the rest).
        let subscription_id = SubscriptionId::new();
        let entry_updates = EntryUpdates {
            updates: vec![
                make_notification("Vehicle.Speed", 100),
                make_notification("Vehicle.Cabin.Temperature", 22),
                make_notification("Vehicle.Body.Lights.IsHighBeamOn", 1),
            ],
        };
        let input = futures::stream::iter(vec![Some(entry_updates)]);
        let output: Vec<_> = convert_to_viss_stream(subscription_id, input, None)
            .collect()
            .await;
        // All 3 updates must be emitted, not just one.
        assert_eq!(output.len(), 3);
        for event in &output {
            assert!(event.is_ok(), "expected Ok event, got Err variant");
        }
    }

    #[tokio::test]
    async fn test_convert_to_viss_stream_empty_updates() {
        // An empty updates batch produces no events (flat_map over empty iterator).
        let subscription_id = SubscriptionId::new();
        let entry_updates = EntryUpdates { updates: vec![] };
        let input = futures::stream::iter(vec![Some(entry_updates)]);
        let output: Vec<_> = convert_to_viss_stream(subscription_id, input, None)
            .collect()
            .await;
        assert_eq!(output.len(), 0);
    }

    #[tokio::test]
    async fn test_convert_to_viss_stream_none_yields_service_unavailable() {
        let subscription_id = SubscriptionId::new();
        let input = futures::stream::iter(vec![None]);
        let output: Vec<_> = convert_to_viss_stream(subscription_id, input, None)
            .collect()
            .await;
        assert_eq!(output.len(), 1);
        assert!(output[0].is_err());
    }

    #[tokio::test]
    async fn test_convert_to_viss_stream_multiple_batches() {
        // Test two consecutive batches, each with different numbers of updates.
        let subscription_id = SubscriptionId::new();
        let batch1 = EntryUpdates {
            updates: vec![
                make_notification("Vehicle.Speed", 42),
                make_notification("Vehicle.Cabin.Temperature", 20),
            ],
        };
        let batch2 = EntryUpdates {
            updates: vec![make_notification("Vehicle.Speed", 43)],
        };
        let input = futures::stream::iter(vec![Some(batch1), Some(batch2)]);
        let output: Vec<_> = convert_to_viss_stream(subscription_id, input, None)
            .collect()
            .await;
        // batch1 has 2 updates, batch2 has 1 → total 3 events.
        assert_eq!(output.len(), 3);
        for event in &output {
            assert!(event.is_ok(), "expected Ok event, got Err variant");
        }
    }

    #[test]
    fn range_filter_matches_or_boundaries() {
        let filter = RangeFilter {
            parameter: vec![
                RangeBoundary {
                    boundary_op: ComparisonOp::Lt,
                    boundary: "50".to_string(),
                    combination_op: Some(CombinationOp::Or),
                },
                RangeBoundary {
                    boundary_op: ComparisonOp::Gt,
                    boundary: "55".to_string(),
                    combination_op: None,
                },
            ],
        };

        assert!(!evaluate_range_filter(&filter, &datapoint(53)));
        assert!(evaluate_range_filter(&filter, &datapoint(60)));
    }

    #[test]
    fn change_filter_requires_threshold_after_initial_event() {
        let mut state = ChangeFilterState::new(ChangeFilter {
            parameter: ChangeParameter {
                logic_op: ComparisonOp::Gt,
                diff: "10".to_string(),
            },
        });

        assert!(state.matches(&datapoint(40)));
        assert!(!state.matches(&datapoint(45)));
        assert!(state.matches(&datapoint(55)));
    }

    #[test]
    fn test_valid_iso8601_durations() {
        // Week designator
        assert!(is_valid_iso8601_duration("P1W"));
        assert!(is_valid_iso8601_duration("P52W"));

        // Date-only durations
        assert!(is_valid_iso8601_duration("P1Y"));
        assert!(is_valid_iso8601_duration("P1M"));
        assert!(is_valid_iso8601_duration("P1D"));
        assert!(is_valid_iso8601_duration("P1Y2M3D"));

        // Time-only durations
        assert!(is_valid_iso8601_duration("PT1H"));
        assert!(is_valid_iso8601_duration("PT30M"));
        assert!(is_valid_iso8601_duration("PT60S"));

        // Combined date and time durations
        assert!(is_valid_iso8601_duration("P1DT12H"));
        assert!(is_valid_iso8601_duration("P1Y2M3DT4H5M6S"));

        // Common real-world examples used in history filter tests
        assert!(is_valid_iso8601_duration("PT10M"));
        assert!(is_valid_iso8601_duration("P1D"));
        assert!(is_valid_iso8601_duration("P1Y"));
    }

    #[test]
    fn test_invalid_iso8601_durations() {
        // Missing 'P' prefix
        assert!(!is_valid_iso8601_duration("1H"));
        assert!(!is_valid_iso8601_duration("T1H"));
        assert!(!is_valid_iso8601_duration("1Y2M"));

        // Empty string
        assert!(!is_valid_iso8601_duration(""));

        // Only 'P' with no components
        assert!(!is_valid_iso8601_duration("P"));

        // Arbitrary strings
        assert!(!is_valid_iso8601_duration("INVALID"));
        assert!(!is_valid_iso8601_duration("last hour"));
        assert!(!is_valid_iso8601_duration("24h"));

        // 'T' present but no time components
        assert!(!is_valid_iso8601_duration("PT"));
        assert!(!is_valid_iso8601_duration("P1DT"));

        // Designator without digits
        assert!(!is_valid_iso8601_duration("PY"));
        assert!(!is_valid_iso8601_duration("PTH"));

        // Unknown designators
        assert!(!is_valid_iso8601_duration("P1X"));
        assert!(!is_valid_iso8601_duration("PT1X"));
    }
}
