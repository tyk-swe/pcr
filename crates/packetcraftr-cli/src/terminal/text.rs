// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) fn render_optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "none".to_owned(), render)
}

/// A duration in milliseconds to the microsecond, such as `12.345ms`.
pub(crate) fn duration_text(duration: std::time::Duration) -> String {
    format!("{:.3}ms", duration.as_secs_f64() * 1_000.0)
}

pub(crate) fn comma_separated<I, T>(values: I) -> String
where
    I: IntoIterator<Item = T>,
    T: ToString,
{
    values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
