use serde::de::DeserializeOwned;

pub(super) use rule_yaml::{Mapping, Value};

pub(super) fn from_str<T>(input: &str) -> Result<T, rule_yaml::Error>
where
    T: DeserializeOwned,
{
    rule_yaml::from_str(input)
}

pub(super) fn from_value<T>(value: Value) -> Result<T, rule_yaml::Error>
where
    T: DeserializeOwned,
{
    rule_yaml::from_value(value)
}
