use std::slice::{Iter, IterMut};

use smol_str::SmolStr;

/// Represents a single SIP header field as a name/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: SmolStr,
    pub value: SmolStr,
}

/// Collection of SIP headers preserving insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<Header>);

impl Headers {
    /// Creates an empty header collection.
    pub fn new() -> Self {
        Self::default()
    }
    /// Builds a header collection from the given vector without additional cloning.
    pub fn from_vec(headers: Vec<Header>) -> Self {
        Self(headers)
    }

    /// Appends a header to the collection.
    pub fn push(&mut self, name: SmolStr, value: SmolStr) {
        self.0.push(Header { name, value });
    }

    /// Returns an iterator over the stored headers.
    pub fn iter(&self) -> Iter<'_, Header> {
        self.0.iter()
    }

    /// Returns a mutable iterator over the stored headers.
    pub fn iter_mut(&mut self) -> IterMut<'_, Header> {
        self.0.iter_mut()
    }

    /// Returns the number of headers present.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the collection does not contain any headers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Finds the first header whose name matches ignoring ASCII case.
    pub fn get(&self, name: &str) -> Option<&SmolStr> {
        self.0
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| &h.value)
    }

    /// Returns all headers with the given name, preserving original order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SmolStr> + 'a {
        self.0
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| &h.value)
    }

    /// Consumes the collection returning the underlying vector.
    pub fn into_inner(self) -> Vec<Header> {
        self.0
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
