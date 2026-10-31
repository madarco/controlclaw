//! A contract one part of an agent provides and others use (the binaries' `contracts.rs`).

use std::sync::{Arc, OnceLock};

/// One implementation, set once.
pub struct Slot<T: ?Sized> {
    name: &'static str,
    cell: OnceLock<Arc<T>>,
}

impl<T: ?Sized> Slot<T> {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            cell: OnceLock::new(),
        }
    }

    /// Two providers for one contract is a wiring mistake and stops the start.
    pub fn set(&self, value: Arc<T>) {
        assert!(self.cell.set(value).is_ok(), "contract {} provided twice", self.name);
    }

    /// The provider, or `None` while its workstream has not filled the slot. Use it only where an
    /// empty slot can only make the box do less (no meeting to leave, no credentials to swap).
    pub fn get(&self) -> Option<Arc<T>> {
        self.cell.get().cloned()
    }

    /// The provider, or the refusal to answer with. Anything that would loosen the firewall,
    /// skip a consent code or let somebody in starts with this: while the slot is empty it is
    /// refused, never applied by default (host rule, 2026-10-28).
    pub fn require(&self) -> Result<Arc<T>, Missing> {
        self.cell.get().cloned().ok_or(Missing(self.name))
    }
}

/// A slot for a contract whose absence must refuse: consent codes, the identity map, sessions.
/// It has no `get()`, so a user cannot treat "not provided yet" as "nothing to check"; the only
/// way to the provider is [`RequiredSlot::require`], which refuses while the slot is empty.
pub struct RequiredSlot<T: ?Sized>(Slot<T>);

impl<T: ?Sized> RequiredSlot<T> {
    pub const fn new(name: &'static str) -> Self {
        Self(Slot::new(name))
    }

    /// Two providers for one contract is a wiring mistake and stops the start.
    pub fn set(&self, value: Arc<T>) {
        self.0.set(value);
    }

    /// The provider, or the refusal to answer with.
    pub fn require(&self) -> Result<Arc<T>, Missing> {
        self.0.require()
    }
}

/// An empty slot where its provider was required. The message is for logs and command results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Missing(pub &'static str);

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not on this build yet, so this is refused", self.0)
    }
}

impl std::error::Error for Missing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_required_slot_only_refuses_or_gives() {
        let s: RequiredSlot<str> = RequiredSlot::new("IdentityMap");
        assert_eq!(s.require().err(), Some(Missing("IdentityMap")));
        s.set(Arc::from("map"));
        assert!(s.require().is_ok());
    }

    #[test]
    fn an_empty_slot_refuses() {
        let s: Slot<str> = Slot::new("ConsentCodes");
        assert_eq!(s.require().err(), Some(Missing("ConsentCodes")));
        s.set(Arc::from("x"));
        assert_eq!(s.require().map(|v| v.to_string()).ok().as_deref(), Some("x"));
    }
}
