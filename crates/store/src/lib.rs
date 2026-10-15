// SPDX-License-Identifier: AGPL-3.0-only

#![feature(iter_macro)]
#![feature(yield_expr)]
#![feature(try_blocks)]
#![feature(raw_os_error_ty)]
#![feature(can_vector)]
#![feature(int_from_ascii)]

//! Data store management for the layer cake Minecraft launcher.

use blake3::Hash;
use std::{
    io,
    path::{Path, PathBuf},
};

use errors::Error;

pub mod errors;

#[cfg(target_os = "linux")]
pub mod linux;

/// Store of data.
///
/// Content-addressed store that manages single "blobs" of data and manifests
/// that describe how they may be assembled into a tree.
///
/// TODO: describe further
#[derive(Debug)]
pub struct Store<Dir> {
    /// Handle to the store.
    inner: Dir,
}

impl<Ba> Store<Ba>
where
    Ba: Backend,
{
    /// List store entries.
    ///
    /// This is best-effort. Entries may change during the process of listing
    /// them.
    pub fn entries(&self) -> impl Iterator<Item = Result<Entry, Error>> {
        self.inner.entries()
    }

    /// Insert a blob into the store, returning its identifier.
    ///
    /// Insertion is performed by using an implementor of the [`StoreWrite`]
    /// trait. This is to permit incremental writes. See its documentation for
    /// more information.
    pub fn insert_blob(&self) -> Result<impl WriteHandle, Error> {
        self.inner.insert_blob()
    }

    /// Insert a tree manifest into the store, returning its
    /// identifier.
    pub fn insert_tree_manifest<'a>(
        &self,
        contents: impl IntoIterator<Item = (&'a Path, Entry)>,
    ) -> Result<Entry, Error> {
        self.inner.insert_tree_manifest(contents)
    }

    /// Insert a composition manifest into the store, returning its
    /// identifier.
    pub fn insert_composition_manifest(
        &self,
        contents: impl IntoIterator<Item = Entry>,
    ) -> Result<Entry, Error> {
        self.inner.insert_composition_manifest(contents)
    }

    /// Read a blob from the store.
    pub fn read_blob(&self, entry: Entry) -> Result<impl io::Read, Error> {
        self.inner.read_blob(entry)
    }

    /// Read a tree manifest from the store.
    pub fn read_tree_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<(PathBuf, Entry), Error>> {
        self.inner.read_tree_manifest(entry)
    }

    /// Read a composition manifest from the store.
    pub fn read_composition_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<Entry, Error>> {
        self.inner.read_composition_manifest(entry)
    }

    /// Classify a store entry.
    pub fn classify_entry(&self, entry: Entry) -> Result<EntryKind, Error> {
        self.inner.classify_entry(entry)
    }

    /// Returns a handle representing a hold on a store entry, preventing it
    /// from being garbage collected.
    ///
    /// If the entry is a manifest, the hold is propagated to the entries it
    /// references.
    pub fn hold_entry(&self, entry: Entry) -> Result<Ba::Hold, Error> {
        self.inner.hold_entry(entry)
    }

    /// Collect garbage in the store, with the given [`Entry`] iterator treated
    /// as the roots for determining liveness of entries.
    ///
    /// Returns an iterator over the store entries which were removed.
    pub fn collect(
        &self,
        roots: impl IntoIterator<Item = Entry>,
    ) -> Result<impl IntoIterator<Item = Entry>, Error> {
        self.inner.collect(roots)
    }
}

/// Abstraction over store operations.
///
/// The underlying implementation must be safe to perform mutations on
/// concurrently, hence the receiver being `&self` and not `&mut self`.
pub trait Backend: sealed::Sealed {
    /// Handle representing a hold on a store entry.
    ///
    /// If the entry is a manifest, the hold is propagated to the entries it
    /// references.
    type Hold;

    /// List store entries.
    fn entries(&self) -> impl Iterator<Item = Result<Entry, Error>>;

    /// Insert a blob into the store, returning its identifier.
    fn insert_blob(&self) -> Result<impl WriteHandle, Error>;

    /// Insert a tree manifest into the store, returning its identifier.
    fn insert_tree_manifest<'a>(
        &self,
        contents: impl IntoIterator<Item = (&'a Path, Entry)>,
    ) -> Result<Entry, Error>;

    /// Insert a composition manifest into the store, returning its identifier.
    fn insert_composition_manifest(
        &self,
        contents: impl IntoIterator<Item = Entry>,
    ) -> Result<Entry, Error>;

    /// Read a blob from the store.
    fn read_blob(&self, entry: Entry) -> Result<impl io::Read, Error>;

    /// Read a tree manifest from the store.
    fn read_tree_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<(PathBuf, Entry), Error>>;

    /// Read a composition manifest from the store.
    fn read_composition_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<Entry, Error>>;

    /// Classify a store entry.
    fn classify_entry(&self, entry: Entry) -> Result<EntryKind, Error>;

    /// Returns a handle representing a hold on a store entry, preventing it
    /// from being garbage collected.
    fn hold_entry(&self, entry: Entry) -> Result<Self::Hold, Error>;

    /// Collect garbage in the store, with the given [`Entry`] iterator treated
    /// as the roots to use for determining liveness of entries.
    ///
    /// Returns an iterator over the store entries which were removed.
    fn collect(
        &self,
        roots: impl IntoIterator<Item = Entry>,
    ) -> Result<impl IntoIterator<Item = Entry>, Error>;
}

/// Kinds of store entries.
#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq)]
pub enum EntryKind {
    /// Opaque blob.
    Blob,

    /// Manifest mapping blobs to paths in a realized file tree.
    TreeManifest,

    /// Manifest composing file tree manifests together.
    CompositionManifest,
}

/// Abstraction over a handle to write an item to the store.
///
/// This is used to support incrementally writing a blob to the store, so that
/// we don't block the task on it.
///
/// Dropping the handle results in the write being abandoned in an
/// implementation-defined staging area, to be cleaned up after garbage
/// collection.
pub trait WriteHandle: io::Write + sealed::Sealed {
    /// Finish writing the blob to the store, returning its [`Entry`].
    fn finish(self) -> Result<Entry, Error>;
}

/// Store entry identifier.
#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Entry {
    /// Unique identifier for the store path + entry kind.
    ///
    /// Some identifier of the entry kind is necessary to distinguish manifests
    /// from opaque blobs with the same contents.
    ///
    /// This is currently the BLAKE3 hash of the contents.
    inner: Hash,
}

impl Entry {
    /// Construct a new store entry identifier from its hash.
    fn new(inner: Hash) -> Self {
        Self { inner }
    }

    /// Extract the BLAKE3 hash of the store entry from its identifier.
    fn into_inner(self) -> Hash {
        self.inner
    }
}

pub(crate) mod sealed {
    //! Module containing the trait used to prevent external implementations of
    //! some public traits.

    /// Trait used to prevent external implementations of some public traits.
    pub trait Sealed {}
}
