// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use packetcraftr::{
    core::{
        self,
        document::{Format, PACKET_DOCUMENT_SCHEMA_V1, PACKET_DOCUMENT_SCHEMA_V2, v2::Document},
        error::{Classification, Kind},
    },
    output,
};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::rendering::{emit_aggregate, write_plain_line, write_stdout_line};
use super::format::AggregateFormat;
use super::registry;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Convert, format)?;
    if arguments.to != "packet/v2" && arguments.to != "packetcraftr.packet/v2" {
        return Err(CliError::from_classification(
            Classification::new("cli.argument", Kind::Cli, Some("specify --to packet/v2")),
            format!(
                "unsupported target schema `{}`; only `packet/v2` is supported",
                arguments.to
            ),
            Vec::new(),
        ));
    }
    let registry = registry()?;
    let targets = collect_targets(&arguments.paths)?;

    let mut converted = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    let mut temp_counter = 0_usize;

    for target in targets {
        match target {
            Target::Stdin => {
                let mut bytes = Vec::new();
                if let Err(source) = io::stdin().read_to_end(&mut bytes) {
                    failed.push(output::convert::FailedEntry {
                        path: "-".to_owned(),
                        error: format!("read stdin failed: {source}"),
                    });
                    if format == AggregateFormat::Text && !arguments.stdout {
                        write_stdout_line(format_args!("failed -: read stdin failed: {source}"))?;
                    }
                    continue;
                }
                let content = match String::from_utf8(bytes) {
                    Ok(c) => c,
                    Err(source) => {
                        failed.push(output::convert::FailedEntry {
                            path: "-".to_owned(),
                            error: format!("stdin is not UTF-8: {source}"),
                        });
                        if format == AggregateFormat::Text && !arguments.stdout {
                            write_stdout_line(format_args!(
                                "failed -: stdin is not UTF-8: {source}"
                            ))?;
                        }
                        continue;
                    }
                };
                let trimmed = content.trim_start();
                let doc_format = if trimmed.starts_with('{') {
                    Format::Json
                } else {
                    Format::Yaml
                };
                let detected = Document::detect_schema(&content);
                if detected == Some(PACKET_DOCUMENT_SCHEMA_V2) {
                    unchanged.push("-".to_owned());
                    if arguments.check {
                        if format == AggregateFormat::Text {
                            write_stdout_line(format_args!("already v2 -"))?;
                        }
                    } else if arguments.stdout || !arguments.check {
                        write_plain_line(format_args!("{content}"))?;
                    }
                } else if detected == Some(PACKET_DOCUMENT_SCHEMA_V1) {
                    let v1_doc = match core::document::Packet::parse_with_resource_limits(
                        &content,
                        doc_format,
                        core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                        core::build::DEFAULT_MAX_LAYERS,
                        core::document::DEFAULT_MAX_DOCUMENT_NESTING,
                    ) {
                        Ok(doc) => doc,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: "-".to_owned(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed -: {e}"))?;
                            }
                            continue;
                        }
                    };
                    let v2_doc = match Document::from_v1(&v1_doc, &registry) {
                        Ok(doc) => doc,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: "-".to_owned(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed -: {e}"))?;
                            }
                            continue;
                        }
                    };
                    let converted_text = match doc_format {
                        Format::Json => v2_doc.to_json_string(),
                        Format::Yaml => v2_doc.to_yaml_string(),
                    };
                    let converted_text = match converted_text {
                        Ok(t) => t,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: "-".to_owned(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed -: {e}"))?;
                            }
                            continue;
                        }
                    };
                    converted.push("-".to_owned());
                    if arguments.check {
                        if format == AggregateFormat::Text {
                            write_stdout_line(format_args!("would convert -"))?;
                        }
                    } else {
                        write_plain_line(format_args!("{converted_text}"))?;
                    }
                } else {
                    let err = "unknown or missing schema in stdin".to_owned();
                    failed.push(output::convert::FailedEntry {
                        path: "-".to_owned(),
                        error: err.clone(),
                    });
                    if format == AggregateFormat::Text && !arguments.stdout {
                        write_stdout_line(format_args!("failed -: {err}"))?;
                    }
                }
            }
            Target::File { path, is_explicit } => {
                let path_str = path.display().to_string();
                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(source) => {
                        if is_explicit {
                            failed.push(output::convert::FailedEntry {
                                path: path_str.clone(),
                                error: source.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed {path_str}: {source}"))?;
                            }
                        }
                        continue;
                    }
                };
                let doc_format = document_format_from_path(&path).unwrap_or_else(|| {
                    if content.trim_start().starts_with('{') {
                        Format::Json
                    } else {
                        Format::Yaml
                    }
                });
                let detected = Document::detect_schema(&content);
                if detected == Some(PACKET_DOCUMENT_SCHEMA_V2) {
                    unchanged.push(path_str.clone());
                    if format == AggregateFormat::Text && !arguments.stdout {
                        write_stdout_line(format_args!("already v2 {path_str}"))?;
                    }
                } else if detected == Some(PACKET_DOCUMENT_SCHEMA_V1) {
                    let v1_doc = match core::document::Packet::parse_with_resource_limits(
                        &content,
                        doc_format,
                        core::document::DEFAULT_MAX_DOCUMENT_BYTES,
                        core::build::DEFAULT_MAX_LAYERS,
                        core::document::DEFAULT_MAX_DOCUMENT_NESTING,
                    ) {
                        Ok(doc) => doc,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: path_str.clone(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed {path_str}: {e}"))?;
                            }
                            continue;
                        }
                    };
                    let v2_doc = match Document::from_v1(&v1_doc, &registry) {
                        Ok(doc) => doc,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: path_str.clone(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed {path_str}: {e}"))?;
                            }
                            continue;
                        }
                    };
                    let converted_text = match doc_format {
                        Format::Json => v2_doc.to_json_string(),
                        Format::Yaml => v2_doc.to_yaml_string(),
                    };
                    let converted_text = match converted_text {
                        Ok(t) => t,
                        Err(e) => {
                            failed.push(output::convert::FailedEntry {
                                path: path_str.clone(),
                                error: e.to_string(),
                            });
                            if format == AggregateFormat::Text && !arguments.stdout {
                                write_stdout_line(format_args!("failed {path_str}: {e}"))?;
                            }
                            continue;
                        }
                    };
                    converted.push(path_str.clone());
                    if arguments.check {
                        if format == AggregateFormat::Text {
                            write_stdout_line(format_args!("would convert {path_str}"))?;
                        }
                    } else if arguments.stdout {
                        write_plain_line(format_args!("{converted_text}"))?;
                    } else {
                        temp_counter = temp_counter.saturating_add(1);
                        let parent = path.parent().unwrap_or_else(|| Path::new("."));
                        let filename = path.file_name().unwrap_or_default().to_string_lossy();
                        let temp_path = parent.join(format!(
                            ".{filename}.tmp_{}_{temp_counter}",
                            std::process::id()
                        ));
                        let write_res = (|| -> io::Result<()> {
                            let mut f = File::create(&temp_path)?;
                            f.write_all(converted_text.as_bytes())?;
                            if !converted_text.ends_with('\n') {
                                f.write_all(b"\n")?;
                            }
                            f.sync_all()?;
                            fs::rename(&temp_path, &path)?;
                            Ok(())
                        })();
                        if let Err(source) = write_res {
                            let _ = fs::remove_file(&temp_path);
                            failed.push(output::convert::FailedEntry {
                                path: path_str.clone(),
                                error: source.to_string(),
                            });
                            if format == AggregateFormat::Text {
                                write_stdout_line(format_args!("failed {path_str}: {source}"))?;
                            }
                            continue;
                        }
                        if format == AggregateFormat::Text {
                            write_stdout_line(format_args!("converted {path_str}"))?;
                        }
                    }
                } else if is_explicit {
                    let err = format!("unknown or missing schema in `{path_str}`");
                    failed.push(output::convert::FailedEntry {
                        path: path_str.clone(),
                        error: err.clone(),
                    });
                    if format == AggregateFormat::Text && !arguments.stdout {
                        write_stdout_line(format_args!("failed {path_str}: {err}"))?;
                    }
                }
            }
        }
    }

    if format == AggregateFormat::Text && !arguments.stdout {
        write_stdout_line(format_args!(
            "converted {}, already v2 {}, failed {}",
            converted.len(),
            unchanged.len(),
            failed.len()
        ))?;
    } else if format == AggregateFormat::Json {
        let result = output::convert::Result {
            converted: converted.clone(),
            unchanged: unchanged.clone(),
            failed: failed.clone(),
        };
        return emit_aggregate(output::contract::Command::Convert, result, Vec::new());
    }

    if !failed.is_empty() {
        return Err(CliError::new(
            2,
            format!("failed to convert {} document(s)", failed.len()),
        ));
    }
    if arguments.check && !converted.is_empty() {
        return Err(CliError::new(
            1,
            format!("{} document(s) would be converted", converted.len()),
        ));
    }

    Ok(())
}

enum Target {
    Stdin,
    File { path: PathBuf, is_explicit: bool },
}

fn collect_targets(paths: &[PathBuf]) -> Result<Vec<Target>, CliError> {
    let mut targets = Vec::new();
    for path in paths {
        if path.as_os_str() == "-" {
            targets.push(Target::Stdin);
        } else if path.is_dir() {
            let mut dir_files = Vec::new();
            collect_dir_files(path, &mut dir_files)?;
            dir_files.sort();
            for f in dir_files {
                targets.push(Target::File {
                    path: f,
                    is_explicit: false,
                });
            }
        } else {
            targets.push(Target::File {
                path: path.clone(),
                is_explicit: true,
            });
        }
    }
    Ok(targets)
}

fn collect_dir_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = fs::read_dir(dir).map_err(|source| {
        CliError::new(
            5,
            format!("read directory {} failed: {source}", dir.display()),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| {
            CliError::new(
                5,
                format!("read directory entry in {} failed: {source}", dir.display()),
            )
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir_files(&path, files)?;
        } else if path.is_file()
            && let Some(ext) = path.extension().and_then(|e| e.to_str())
        {
            let ext_lower = ext.to_ascii_lowercase();
            if ext_lower == "json" || ext_lower == "yaml" || ext_lower == "yml" {
                files.push(path);
            }
        }
    }
    Ok(())
}

fn document_format_from_path(path: &Path) -> Option<Format> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(Format::Json),
        "yaml" | "yml" => Some(Format::Yaml),
        _ => None,
    }
}
