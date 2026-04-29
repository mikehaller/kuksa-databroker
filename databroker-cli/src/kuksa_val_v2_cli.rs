/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
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

use databroker_proto::kuksa::val::v2 as proto;
use kuksa_common::ClientTraitV2;
use kuksa_val_v2::KuksaClientV2;

use tokio_stream::StreamExt;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ansi_term::Color;

use crate::cli::ParseError;
use crate::cli::{self, Cli};
use linefeed::complete::{Completer, Completion, Suffix};
use linefeed::terminal::Terminal;
use linefeed::{Command, Interface, Prompter, ReadResult};

const VERSION: &str = "kuksa.val.v2";
const TIMEOUT: Duration = Duration::from_millis(500);

const CLI_COMMANDS: &[(&str, &str, &str)] = &[
    ("connect", "[URI]", "Connect to server"),
    ("get", "<PATH> [[PATH] ...]", "Get signal value(s)"),
    ("actuate", "<PATH> <VALUE>", "Set actuator signal"),
    (
        "subscribe",
        "<PATH> [[PATH] ...]",
        "Subscribe to signals (comma or space separated)",
    ),
    ("publish", "<PATH> <VALUE>", "Publish signal value"),
    (
        "metadata",
        "[PATTERN]",
        "Fetch metadata. Provide PATTERN to list metadata of signals matching pattern.",
    ),
    ("token", "<TOKEN>", "Use TOKEN as access token"),
    (
        "token-file",
        "<FILE>",
        "Use content of FILE as access token",
    ),
    ("help", "", "You're looking at it."),
    ("quit", "", "Quit"),
];

fn print_usage(command: impl AsRef<str>) {
    for (cmd, usage, _) in CLI_COMMANDS {
        if *cmd == command.as_ref() {
            println!("Usage: {cmd} {usage}");
        }
    }
}

async fn handle_list_metadata(
    root: &str,
    client: &mut KuksaClientV2,
) -> Result<Option<Vec<proto::Metadata>>, Box<dyn std::error::Error>> {
    match client
        .list_metadata((root.to_string(), "*".to_string()))
        .await
    {
        Ok(metadata) => Ok(Some(metadata)),
        Err(kuksa_common::ClientError::Status(status)) => {
            cli::print_resp_err("metadata", &status)?;
            Ok(None)
        }
        Err(kuksa_common::ClientError::Connection(msg)) => {
            cli::print_error("metadata", msg)?;
            Ok(None)
        }
        Err(kuksa_common::ClientError::Function(msg)) => {
            cli::print_resp_err_fmt("metadata", format_args!("Error {msg:?}"))?;
            Ok(None)
        }
    }
}

async fn handle_get_command(
    paths: Vec<String>,
    client: &mut KuksaClientV2,
) -> Result<(), Box<dyn std::error::Error>> {
    match client.get_values(paths).await {
        Ok(datapoints) => {
            cli::print_resp_ok("get")?;
            for dp in datapoints {
                if let Some(value) = &dp.value {
                    println!("{}", DisplayValue(value));
                } else {
                    println!("NotAvailable");
                }
            }
        }
        Err(kuksa_common::ClientError::Status(err)) => {
            cli::print_resp_err("get", &err)?;
        }
        Err(kuksa_common::ClientError::Connection(msg)) => {
            cli::print_error("get", msg)?;
        }
        Err(kuksa_common::ClientError::Function(msg)) => {
            cli::print_resp_err_fmt("get", format_args!("Error {msg:?}"))?;
        }
    }
    Ok(())
}

async fn handle_publish_command(
    path: &str,
    value_str: &str,
    client: &mut KuksaClientV2,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch metadata to determine data type for parsing
    let metadata_list = handle_list_metadata(path, client).await?;

    let data_type = metadata_list
        .as_ref()
        .and_then(|list| list.iter().find(|m| m.path == path))
        .and_then(|m| proto::DataType::try_from(m.data_type).ok());

    let data_type = match data_type {
        Some(dt) => dt,
        None => {
            cli::print_error("publish", format!("Could not find metadata for '{path}'"))?;
            return Ok(());
        }
    };

    match try_into_value(value_str, data_type) {
        Ok(value) => match client.publish_value(path.to_string(), value).await {
            Ok(_) => cli::print_resp_ok("publish")?,
            Err(kuksa_common::ClientError::Status(status)) => {
                cli::print_resp_err("publish", &status)?
            }
            Err(kuksa_common::ClientError::Connection(msg)) => {
                cli::print_error("publish", msg)?
            }
            Err(kuksa_common::ClientError::Function(msg)) => {
                cli::print_resp_err_fmt("publish", format_args!("Error {msg:?}"))?;
            }
        },
        Err(_) => {
            println!("Could not parse \"{value_str}\" as {data_type:?}");
        }
    }
    Ok(())
}

async fn handle_actuate_command(
    path: &str,
    value_str: &str,
    client: &mut KuksaClientV2,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch metadata to determine data type and confirm entry is actuator
    let metadata_list = handle_list_metadata(path, client).await?;

    let metadata = metadata_list
        .as_ref()
        .and_then(|list| list.iter().find(|m| m.path == path));

    let metadata = match metadata {
        Some(m) => m,
        None => {
            cli::print_error("actuate", format!("Could not find metadata for '{path}'"))?;
            return Ok(());
        }
    };

    let entry_type = proto::EntryType::try_from(metadata.entry_type)
        .unwrap_or(proto::EntryType::Unspecified);
    if entry_type != proto::EntryType::Actuator {
        cli::print_error("actuate", format!("'{path}' is not an actuator"))?;
        return Ok(());
    }

    let data_type = match proto::DataType::try_from(metadata.data_type).ok() {
        Some(dt) => dt,
        None => {
            cli::print_error("actuate", "Unknown data type in metadata")?;
            return Ok(());
        }
    };

    match try_into_value(value_str, data_type) {
        Ok(value) => match client.actuate(path.to_string(), value).await {
            Ok(_) => cli::print_resp_ok("actuate")?,
            Err(kuksa_common::ClientError::Status(status)) => {
                cli::print_resp_err("actuate", &status)?
            }
            Err(kuksa_common::ClientError::Connection(msg)) => {
                cli::print_error("actuate", msg)?
            }
            Err(kuksa_common::ClientError::Function(msg)) => {
                cli::print_resp_err_fmt("actuate", format_args!("Error {msg:?}"))?;
            }
        },
        Err(_) => {
            println!("Could not parse \"{value_str}\" as {data_type:?}");
        }
    }
    Ok(())
}

pub async fn kuksa_val_v2_main(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Using {VERSION}");

    let mut subscription_nbr = 1;

    let completer = CliCompleter::new();
    let interface = Arc::new(Interface::new("client")?);
    interface.set_completer(Arc::new(completer));

    interface.define_function("enter-function", Arc::new(cli::EnterFunction));
    interface.bind_sequence("\r", Command::from_str("enter-function"));
    interface.bind_sequence("\n", Command::from_str("enter-function"));

    cli::set_disconnected_prompt(&interface);

    let mut cli = _cli;
    let mut client = KuksaClientV2::new(kuksa_common::to_uri(cli.get_server())?);

    if let Some(token_filename) = cli.get_token_file() {
        let token = std::fs::read_to_string(token_filename)?;
        client.basic_client.set_access_token(token)?;
    }

    #[cfg(feature = "tls")]
    if let Some(ca_cert_filename) = cli.get_ca_cert() {
        let pem = std::fs::read(ca_cert_filename)?;
        let ca_cert = tonic::transport::Certificate::from_pem(pem);
        let tls_config = tonic::transport::ClientTlsConfig::new().ca_certificate(ca_cert);
        client.basic_client.set_tls_config(tls_config);
    }

    let mut connection_state_subscription = client.basic_client.subscribe_to_connection_state();
    let interface_ref = interface.clone();

    tokio::spawn(async move {
        while let Some(state) = connection_state_subscription.next().await {
            match state {
                Ok(state) => match state {
                    kuksa_common::ConnectionState::Connected => {
                        cli::set_connected_prompt(&interface_ref, VERSION.to_string());
                    }
                    kuksa_common::ConnectionState::Disconnected => {
                        cli::set_disconnected_prompt(&interface_ref);
                    }
                },
                Err(err) => {
                    cli::print_error(
                        "connection",
                        format!("Connection state subscription failed: {err}"),
                    )
                    .unwrap_or_default();
                }
            }
        }
    });

    // Handle non-interactive subcommands
    match cli.get_command() {
        Some(cli::Commands::Get { paths }) => {
            return handle_get_command(paths, &mut client).await;
        }
        Some(cli::Commands::Set { path: _, value: _ }) => {
            eprintln!("The 'set' command is not supported for kuksa.val.v2. Use 'publish' or 'actuate' instead.");
            return Ok(());
        }
        Some(cli::Commands::Actuate { path, value }) => {
            return handle_actuate_command(&path, &value, &mut client).await;
        }
        Some(cli::Commands::Publish { path, value }) => {
            return handle_publish_command(&path, &value, &mut client).await;
        }
        None => {
            // No subcommand => run interactive client
            let version = match option_env!("CARGO_PKG_VERSION") {
                Some(version) => format!("v{version}"),
                None => String::new(),
            };
            cli::print_logo(version);

            match client.basic_client.try_connect().await {
                Ok(()) => {
                    // Show server info in prompt if available
                    let server_label = match client.get_server_info().await {
                        Ok(info) => format!("{VERSION} ({})", info.version),
                        Err(_) => VERSION.to_string(),
                    };
                    cli::set_connected_prompt(&interface, server_label);

                    cli::print_info(format!(
                        "Successfully connected to {}",
                        client.basic_client.get_uri()
                    ))?;

                    // Populate tab-completion with all signal paths
                    if let Some(entries) = handle_list_metadata("", &mut client).await? {
                        interface
                            .set_completer(Arc::new(CliCompleter::from_metadata(&entries)));
                    }
                }
                Err(err) => {
                    cli::print_error("connect", format!("{err}"))?;
                }
            }
        }
    };

    loop {
        if let Some(res) = interface.read_line_step(Some(TIMEOUT))? {
            match res {
                ReadResult::Input(line) => {
                    let (cmd, args) = cli::split_first_word(&line);
                    match cmd {
                        "help" => {
                            println!();
                            for &(cmd, args, help) in CLI_COMMANDS {
                                println!("  {:24} {}", format!("{cmd} {args}"), help);
                            }
                            println!();
                        }
                        "get" => {
                            interface.add_history_unique(line.clone());

                            if args.is_empty() {
                                print_usage(cmd);
                                continue;
                            }
                            let paths = args
                                .split_whitespace()
                                .map(|path| path.to_owned())
                                .collect();

                            handle_get_command(paths, &mut client).await?
                        }
                        "token" => {
                            interface.add_history_unique(line.clone());

                            if args.is_empty() {
                                print_usage(cmd);
                                continue;
                            }

                            match client.basic_client.set_access_token(args) {
                                Ok(()) => {
                                    cli::print_info("Access token set.")?;
                                    if let Some(entries) =
                                        handle_list_metadata("", &mut client).await?
                                    {
                                        interface.set_completer(Arc::new(
                                            CliCompleter::from_metadata(&entries),
                                        ));
                                    }
                                }
                                Err(err) => {
                                    cli::print_error(cmd, format!("Malformed token: {err}"))?
                                }
                            }
                        }
                        "token-file" => {
                            interface.add_history_unique(line.clone());

                            if args.is_empty() {
                                print_usage(cmd);
                                continue;
                            }

                            let token_filename = args.trim();
                            match std::fs::read_to_string(token_filename) {
                                Ok(token) => match client.basic_client.set_access_token(token) {
                                    Ok(()) => {
                                        cli::print_info("Access token set.")?;
                                        if let Some(entries) =
                                            handle_list_metadata("", &mut client).await?
                                        {
                                            interface.set_completer(Arc::new(
                                                CliCompleter::from_metadata(&entries),
                                            ));
                                        }
                                    }
                                    Err(err) => {
                                        cli::print_error(cmd, format!("Malformed token: {err}"))?
                                    }
                                },
                                Err(err) => cli::print_error(
                                    cmd,
                                    format!(
                                        "Failed to open token file \"{token_filename}\": {err}"
                                    ),
                                )?,
                            }
                        }
                        "actuate" => {
                            interface.add_history_unique(line.clone());

                            let (path, value) = cli::split_first_word(args);

                            if value.is_empty() {
                                print_usage(cmd);
                                continue;
                            }

                            handle_actuate_command(path, value, &mut client).await?
                        }
                        "publish" => {
                            interface.add_history_unique(line.clone());

                            let (path, value) = cli::split_first_word(args);

                            if value.is_empty() {
                                print_usage(cmd);
                                continue;
                            }

                            handle_publish_command(path, value, &mut client).await?
                        }
                        "subscribe" => {
                            interface.add_history_unique(line.clone());

                            if args.is_empty() {
                                print_usage(cmd);
                                continue;
                            }

                            let signal_paths: Vec<String> = args
                                .split_whitespace()
                                .map(|s| s.to_string())
                                .collect();

                            match client.subscribe(signal_paths, None).await {
                                Ok(mut stream) => {
                                    let iface = interface.clone();
                                    tokio::spawn(async move {
                                        let sub_disp = format!("[{subscription_nbr}]");
                                        let sub_disp_pad = " ".repeat(sub_disp.len());
                                        let sub_disp_color =
                                            format!("{}", Color::White.dimmed().paint(&sub_disp));

                                        loop {
                                            match stream.message().await {
                                                Ok(Some(resp)) => {
                                                    use std::fmt::Write;
                                                    let mut output = String::new();
                                                    let mut first_line = true;
                                                    for (path, datapoint) in resp.entries {
                                                        if first_line {
                                                            first_line = false;
                                                            write!(
                                                                output,
                                                                "{} ",
                                                                &sub_disp_color,
                                                            )
                                                            .unwrap();
                                                        } else {
                                                            write!(
                                                                output,
                                                                "{} ",
                                                                &sub_disp_pad,
                                                            )
                                                            .unwrap();
                                                        }
                                                        if let Some(value) = &datapoint.value {
                                                            writeln!(
                                                                output,
                                                                "{path}: {}",
                                                                DisplayValue(value)
                                                            )
                                                            .unwrap();
                                                        } else {
                                                            writeln!(
                                                                output,
                                                                "{path}: NotAvailable"
                                                            )
                                                            .unwrap();
                                                        }
                                                    }
                                                    write!(iface, "{output}").unwrap();
                                                }
                                                Ok(None) => {
                                                    writeln!(
                                                        iface,
                                                        "{} {}",
                                                        Color::Red.dimmed().paint(&sub_disp),
                                                        Color::White.dimmed().paint(
                                                            "Server gone. Subscription stopped"
                                                        ),
                                                    )
                                                    .unwrap();
                                                    break;
                                                }
                                                Err(err) => {
                                                    write!(
                                                        iface,
                                                        "{} {}",
                                                        &sub_disp_color,
                                                        Color::Red.dimmed().paint(format!(
                                                            "Channel error: {err}"
                                                        ))
                                                    )
                                                    .unwrap();
                                                    break;
                                                }
                                            }
                                        }
                                    });

                                    cli::print_resp_ok(cmd)?;
                                    cli::print_info(format!(
                                        "Subscription is now running in the background. Received data is identified by [{subscription_nbr}]."
                                    ))?;
                                    subscription_nbr += 1;
                                }
                                Err(kuksa_common::ClientError::Status(status)) => {
                                    cli::print_resp_err(cmd, &status)?
                                }
                                Err(kuksa_common::ClientError::Connection(msg)) => {
                                    cli::print_error(cmd, msg)?
                                }
                                Err(kuksa_common::ClientError::Function(msg)) => {
                                    cli::print_resp_err_fmt(
                                        cmd,
                                        format_args!("Error {msg:?}"),
                                    )?
                                }
                            }
                        }
                        "connect" => {
                            interface.add_history_unique(line.clone());
                            if !client.basic_client.is_connected() || !args.is_empty() {
                                if args.is_empty() {
                                    match client.basic_client.try_connect().await {
                                        Ok(()) => {
                                            cli::print_info(format!(
                                                "[{cmd}] Successfully connected to {}",
                                                client.basic_client.get_uri()
                                            ))?;
                                        }
                                        Err(err) => {
                                            cli::print_error(cmd, format!("{err}"))?;
                                        }
                                    }
                                } else {
                                    match kuksa_common::to_uri(args) {
                                        Ok(valid_uri) => {
                                            match client
                                                .basic_client
                                                .try_connect_to(valid_uri)
                                                .await
                                            {
                                                Ok(()) => {
                                                    cli::print_info(format!(
                                                        "[{cmd}] Successfully connected to {}",
                                                        client.basic_client.get_uri()
                                                    ))?;
                                                }
                                                Err(err) => {
                                                    cli::print_error(cmd, format!("{err}"))?;
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            cli::print_error(
                                                cmd,
                                                format!(
                                                    "Failed to parse endpoint address: {err}"
                                                ),
                                            )?;
                                        }
                                    }
                                };
                                if client.basic_client.is_connected() {
                                    if let Some(entries) =
                                        handle_list_metadata("", &mut client).await?
                                    {
                                        interface.set_completer(Arc::new(
                                            CliCompleter::from_metadata(&entries),
                                        ));
                                    }
                                }
                            };
                        }
                        "metadata" => {
                            interface.add_history_unique(line.clone());

                            let root = args.trim();

                            if root.is_empty() {
                                cli::print_info("If you want to list metadata of signals, use `metadata PATTERN`")?;
                            } else if let Some(entries) =
                                handle_list_metadata(root, &mut client).await?
                            {
                                cli::print_resp_ok(cmd)?;
                                if !entries.is_empty() {
                                    let max_len_path =
                                        entries.iter().fold(0, |mut max_len, item| {
                                            if item.path.len() > max_len {
                                                max_len = item.path.len();
                                            }
                                            max_len
                                        });

                                    cli::print_info(format!(
                                        "{:<max_len_path$} {:<10} {:<9}",
                                        "Path", "Entry type", "Data type"
                                    ))?;

                                    for entry in &entries {
                                        let entry_type = proto::EntryType::try_from(entry.entry_type).ok();
                                        let data_type = proto::DataType::try_from(entry.data_type).ok();
                                        println!(
                                            "{:<max_len_path$} {:<10} {:<9}",
                                            entry.path,
                                            DisplayEntryType(entry_type),
                                            DisplayDataType(data_type),
                                        );
                                    }
                                }
                            }
                        }
                        "quit" | "exit" => {
                            println!("Bye bye!");
                            break;
                        }
                        "" => {} // Ignore empty input
                        _ => {
                            println!(
                                "Unknown command. See `help` for a list of available commands."
                            );
                            interface.add_history_unique(line.clone());
                        }
                    }
                }
                ReadResult::Eof => {
                    println!("Bye bye!");
                    break;
                }
                ReadResult::Signal(sig) => {
                    if sig == linefeed::Signal::Interrupt {
                        interface.cancel_read_line()?;
                    }
                    let _ = writeln!(interface, "signal received: {sig:?}");
                }
            }
        }
    }

    Ok(())
}

// ─── Tab completion ───────────────────────────────────────────────────────────

struct CliCompleter {
    paths: PathPart,
}

#[derive(Debug)]
struct PathPart {
    rel_path: String,
    full_path: String,
    children: HashMap<String, PathPart>,
}

impl PathPart {
    fn new() -> Self {
        PathPart {
            rel_path: "".into(),
            full_path: "".into(),
            children: HashMap::new(),
        }
    }
}

impl CliCompleter {
    fn new() -> CliCompleter {
        CliCompleter {
            paths: PathPart::new(),
        }
    }

    fn from_metadata(entries: &[proto::Metadata]) -> CliCompleter {
        let mut root = PathPart::new();
        for entry in entries {
            let mut parent = &mut root;
            let parts = entry.path.split('.');
            for part in parts {
                let full_path = match parent.full_path.as_str() {
                    "" => part.to_owned(),
                    _ => format!("{}.{}", parent.full_path, part),
                };
                let child = parent
                    .children
                    .entry(part.to_lowercase())
                    .or_insert(PathPart {
                        rel_path: part.to_owned(),
                        full_path,
                        children: HashMap::new(),
                    });
                parent = child;
            }
        }
        CliCompleter { paths: root }
    }

    fn complete_entry_path(&self, word: &str) -> Option<Vec<Completion>> {
        if !self.paths.children.is_empty() {
            let mut res = Vec::new();

            let lowercase_word = word.to_lowercase();
            let mut parts = lowercase_word.split('.');
            let mut path = &self.paths;
            loop {
                match parts.next() {
                    Some(part) => match path.children.get(part) {
                        Some(matching_path) => {
                            path = matching_path;
                        }
                        None => {
                            for (path_part_lower, path_spec) in &path.children {
                                if path_part_lower.starts_with(part) {
                                    if !path_spec.children.is_empty() {
                                        res.push(Completion {
                                            completion: format!("{}.", path_spec.full_path),
                                            display: Some(format!("{}.", path_spec.rel_path)),
                                            suffix: Suffix::None,
                                        });
                                    } else {
                                        res.push(Completion {
                                            completion: path_spec.full_path.to_owned(),
                                            display: Some(path_spec.rel_path.to_owned()),
                                            suffix: Suffix::Default,
                                        });
                                    }
                                }
                            }
                            break;
                        }
                    },
                    None => {
                        for path_spec in path.children.values() {
                            if !path_spec.children.is_empty() {
                                res.push(Completion {
                                    completion: format!("{}.", path_spec.full_path),
                                    display: Some(format!("{}.", path_spec.rel_path)),
                                    suffix: Suffix::None,
                                });
                            } else {
                                res.push(Completion {
                                    completion: path_spec.full_path.to_owned(),
                                    display: Some(path_spec.rel_path.to_owned()),
                                    suffix: Suffix::Default,
                                });
                            }
                        }
                        break;
                    }
                }
            }

            res.sort_by(|a, b| a.display().cmp(&b.display()));
            Some(res)
        } else {
            None
        }
    }
}

impl<Term: Terminal> Completer<Term> for CliCompleter {
    fn complete(
        &self,
        word: &str,
        prompter: &Prompter<Term>,
        start: usize,
        _end: usize,
    ) -> Option<Vec<Completion>> {
        let line = prompter.buffer();
        let mut words = line[..start].split_whitespace();

        match words.next() {
            // Complete command name
            None => {
                let mut compls = Vec::new();
                for &(cmd, _, _) in CLI_COMMANDS {
                    if cmd.starts_with(word) {
                        compls.push(Completion {
                            completion: cmd.to_owned(),
                            display: None,
                            suffix: Suffix::default(),
                        });
                    }
                }
                Some(compls)
            }
            Some("actuate") | Some("publish") => {
                if words.count() == 0 {
                    self.complete_entry_path(word)
                } else {
                    None
                }
            }
            Some("get") | Some("metadata") | Some("subscribe") => {
                self.complete_entry_path(word)
            }
            Some("token-file") => {
                let path_completer = linefeed::complete::PathCompleter;
                path_completer.complete(word, prompter, start, _end)
            }
            _ => None,
        }
    }
}

// ─── Display helpers ──────────────────────────────────────────────────────────

struct DisplayDataType(Option<proto::DataType>);
struct DisplayEntryType(Option<proto::EntryType>);
struct DisplayValue<'a>(&'a proto::Value);

fn display_array<T>(f: &mut fmt::Formatter<'_>, array: &[T]) -> fmt::Result
where
    T: fmt::Display,
{
    f.write_str("[")?;
    let real_delimiter = ", ";
    let mut delimiter = "";
    for value in array {
        write!(f, "{delimiter}")?;
        delimiter = real_delimiter;
        write!(f, "{value}")?;
    }
    f.write_str("]")
}

impl fmt::Display for DisplayValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.typed_value {
            Some(proto::value::TypedValue::String(v)) => f.pad(&format!("'{v}'")),
            Some(proto::value::TypedValue::Bool(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::Int32(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::Int64(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::Uint32(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::Uint64(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::Float(v)) => f.pad(&format!("{v:.2}")),
            Some(proto::value::TypedValue::Double(v)) => f.pad(&format!("{v}")),
            Some(proto::value::TypedValue::StringArray(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::BoolArray(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::Int32Array(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::Int64Array(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::Uint32Array(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::Uint64Array(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::FloatArray(a)) => display_array(f, &a.values),
            Some(proto::value::TypedValue::DoubleArray(a)) => display_array(f, &a.values),
            None => f.pad("None"),
        }
    }
}

impl fmt::Display for DisplayEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(entry_type) => f.pad(&format!("{entry_type:?}")),
            None => f.pad("Unknown"),
        }
    }
}

impl fmt::Display for DisplayDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(data_type) => f.pad(&format!("{data_type:?}")),
            None => f.pad("Unknown"),
        }
    }
}

// ─── Value parsing ────────────────────────────────────────────────────────────

fn try_into_value(input: &str, data_type: proto::DataType) -> Result<proto::Value, ParseError> {
    let typed = match data_type {
        proto::DataType::String => {
            proto::value::TypedValue::String(input.to_owned())
        }
        proto::DataType::StringArray => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::StringArray(proto::StringArray { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Boolean => match input.parse::<bool>() {
            Ok(v) => proto::value::TypedValue::Bool(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::BooleanArray => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::BoolArray(proto::BoolArray { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Int8 => match input.parse::<i8>() {
            Ok(v) => proto::value::TypedValue::Int32(v as i32),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Int8Array => {
            match cli::get_array_from_input::<i8>(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Int32Array(proto::Int32Array {
                    values: v.into_iter().map(|x| x as i32).collect(),
                }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Int16 => match input.parse::<i16>() {
            Ok(v) => proto::value::TypedValue::Int32(v as i32),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Int16Array => {
            match cli::get_array_from_input::<i16>(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Int32Array(proto::Int32Array {
                    values: v.into_iter().map(|x| x as i32).collect(),
                }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Int32 => match input.parse::<i32>() {
            Ok(v) => proto::value::TypedValue::Int32(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Int32Array => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Int32Array(proto::Int32Array { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Int64 => match input.parse::<i64>() {
            Ok(v) => proto::value::TypedValue::Int64(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Int64Array => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Int64Array(proto::Int64Array { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Uint8 => match input.parse::<u8>() {
            Ok(v) => proto::value::TypedValue::Uint32(v as u32),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Uint8Array => {
            match cli::get_array_from_input::<u8>(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Uint32Array(proto::Uint32Array {
                    values: v.into_iter().map(|x| x as u32).collect(),
                }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Uint16 => match input.parse::<u16>() {
            Ok(v) => proto::value::TypedValue::Uint32(v as u32),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Uint16Array => {
            match cli::get_array_from_input::<u16>(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Uint32Array(proto::Uint32Array {
                    values: v.into_iter().map(|x| x as u32).collect(),
                }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Uint32 => match input.parse::<u32>() {
            Ok(v) => proto::value::TypedValue::Uint32(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Uint32Array => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Uint32Array(proto::Uint32Array { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Uint64 => match input.parse::<u64>() {
            Ok(v) => proto::value::TypedValue::Uint64(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::Uint64Array => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::Uint64Array(proto::Uint64Array { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Float => match input.parse::<f32>() {
            Ok(v) => proto::value::TypedValue::Float(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::FloatArray => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::FloatArray(proto::FloatArray { values: v }),
                Err(e) => return Err(e),
            }
        }
        proto::DataType::Double => match input.parse::<f64>() {
            Ok(v) => proto::value::TypedValue::Double(v),
            Err(_) => return Err(ParseError {}),
        },
        proto::DataType::DoubleArray => {
            match cli::get_array_from_input(input.to_owned()) {
                Ok(v) => proto::value::TypedValue::DoubleArray(proto::DoubleArray { values: v }),
                Err(e) => return Err(e),
            }
        }
        _ => return Err(ParseError {}),
    };
    Ok(proto::Value {
        typed_value: Some(typed),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_string() {
        let v = try_into_value("hello", proto::DataType::String).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::String(ref s)) if s == "hello"
        ));
    }

    #[test]
    fn test_parse_bool() {
        let v = try_into_value("true", proto::DataType::Boolean).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::Bool(true))
        ));
        let v = try_into_value("false", proto::DataType::Boolean).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::Bool(false))
        ));
        assert!(try_into_value("notabool", proto::DataType::Boolean).is_err());
    }

    #[test]
    fn test_parse_int8() {
        let v = try_into_value("100", proto::DataType::Int8).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::Int32(100))
        ));
        assert!(try_into_value("300", proto::DataType::Int8).is_err());
    }

    #[test]
    fn test_parse_uint32() {
        let v = try_into_value("42", proto::DataType::Uint32).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::Uint32(42))
        ));
    }

    #[test]
    fn test_parse_float() {
        let v = try_into_value("3.14", proto::DataType::Float).unwrap();
        assert!(matches!(
            v.typed_value,
            Some(proto::value::TypedValue::Float(_))
        ));
    }

    #[test]
    fn test_parse_string_array() {
        let v =
            try_into_value("[a, b, c]", proto::DataType::StringArray).unwrap();
        if let Some(proto::value::TypedValue::StringArray(arr)) = v.typed_value {
            assert_eq!(arr.values, vec!["a", "b", "c"]);
        } else {
            panic!("Expected StringArray");
        }
    }
}
