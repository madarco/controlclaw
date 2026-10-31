//! A field that can be absent, `null`, or a value, and keeps which of the three it was.
//!
//! `Option<T>` folds absent and `null` into `None`, so a file read and written again would gain or
//! lose `"x": null` keys. The addon mostly treats both the same (`dict.get`), but the TS side does
//! not always (`placeholder: null` is how a revoked grant travels), and a round trip must not
//! change what the other side reads. Use with
//! `#[serde(default, skip_serializing_if = "Maybe::is_absent")]`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Maybe<T> {
    #[default]
    Absent,
    Null,
    Value(T),
}

impl<T> Maybe<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Maybe::Absent)
    }

    /// The value, treating absent and `null` alike, as the addon's `dict.get` does.
    pub fn get(&self) -> Option<&T> {
        match self {
            Maybe::Value(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            Maybe::Value(v) => Some(v),
            _ => None,
        }
    }
}

impl<T> From<Option<T>> for Maybe<T> {
    /// `None` becomes `Absent`: what a writer that leaves the key out means.
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => Maybe::Value(v),
            None => Maybe::Absent,
        }
    }
}

impl<T: Serialize> Serialize for Maybe<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            // Only reached when a field forgot `skip_serializing_if`; null is the safe reading.
            Maybe::Absent | Maybe::Null => s.serialize_none(),
            Maybe::Value(v) => v.serialize(s),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Maybe<T> {
    /// Only called when the key is there (absent comes from `#[serde(default)]`).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            Some(v) => Maybe::Value(v),
            None => Maybe::Null,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct S {
        #[serde(default, skip_serializing_if = "Maybe::is_absent")]
        a: Maybe<String>,
    }

    #[test]
    fn keeps_absent_null_and_value_apart() -> serde_json::Result<()> {
        for text in [r#"{}"#, r#"{"a":null}"#, r#"{"a":"x"}"#] {
            let s: S = serde_json::from_str(text)?;
            assert_eq!(serde_json::to_string(&s)?, text);
        }
        Ok(())
    }
}
