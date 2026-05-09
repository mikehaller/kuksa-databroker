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
    future,
    stream::{AbortHandle, Abortable},
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
    stream
        .map(move |item| {
            let ts = SystemTime::now().into();
            let subscription_id = subscription_id.clone();
            match item {
                Some(mut value) => match value.updates.pop() {
                    Some(item) => match (item.update.path, item.update.datapoint) {
                        (Some(path), Some(datapoint)) => {
                            if let Some(state) = &mut filter_state {
                                if !state.matches(&datapoint) {
                                    return None;
                                }
                            }
                            Some(Ok(SubscriptionEvent {
                                subscription_id,
                                data: Data::Object(DataObject {
                                    path: path.into(),
                                    dp: datapoint.into(),
                                }),
                                ts,
                            }))
                        }
                        (_, _) => Some(Err(SubscriptionErrorEvent {
                            subscription_id,
                            error: Error::InternalServerError,
                            ts,
                        })),
                    },
                    None => Some(Err(SubscriptionErrorEvent {
                        subscription_id,
                        error: Error::InternalServerError,
                        ts,
                    })),
                },
                // if None, it means the provider(is not available), meaning we should return the VISS error service_unavailable
                None => Some(Err(SubscriptionErrorEvent {
                    subscription_id,
                    error: Error::ServiceUnavailable,
                    ts,
                })),
            }
        })
        .filter_map(future::ready)
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

    fn datapoint(value: i32) -> broker::Datapoint {
        broker::Datapoint {
            ts: SystemTime::now(),
            source_ts: None,
            value: broker::DataValue::Int32(value),
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
}
