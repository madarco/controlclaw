//! A map that keeps its keys in insertion order, as a JavaScript object does (the stores'
//! `Record<string, …>` fields): a store written here lists its entries in the order the Node
//! build would, and `Object.values` order is kept on the wire.

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub struct OrdMap<V>(Vec<(String, V)>);

impl<V> Default for OrdMap<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<V> OrdMap<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, k: &str) -> Option<&V> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, k: &str) -> Option<&mut V> {
        self.0.iter_mut().find(|(n, _)| n == k).map(|(_, v)| v)
    }

    pub fn contains_key(&self, k: &str) -> bool {
        self.get(k).is_some()
    }

    /// A key already there keeps its place, as `obj[k] = v` does.
    pub fn insert(&mut self, k: String, v: V) {
        match self.get_mut(&k) {
            Some(slot) => *slot = v,
            None => self.0.push((k, v)),
        }
    }

    pub fn remove(&mut self, k: &str) -> Option<V> {
        let i = self.0.iter().position(|(n, _)| n == k)?;
        Some(self.0.remove(i).1)
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&String, &V) -> bool) {
        self.0.retain(|(k, v)| keep(k, v));
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, v)| v)
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.0.iter_mut().map(|(_, v)| v)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(k, _)| k)
    }
}

impl<V: Serialize> Serialize for OrdMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrdMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V_<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for V_<V> {
            type Value = OrdMap<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<OrdMap<V>, A::Error> {
                let mut out = OrdMap::new();
                while let Some((k, v)) = a.next_entry::<String, V>()? {
                    out.insert(k, v);
                }
                Ok(out)
            }
        }
        d.deserialize_map(V_(std::marker::PhantomData))
    }
}
