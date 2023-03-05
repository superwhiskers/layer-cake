use async_trait::async_trait;
use futures::stream::{Stream, TryStreamExt};
use std::error::Error;
use tokio::io::AsyncRead;

/// Kinds of [`Resource`]s
pub enum ResourceKind {
    /// A configuration file
    ConfigFile,

    // A game modification
    Mod,

    /// Auxiliary data (assets, native libraries, etc)
    Auxiliary,

    /// A Java library
    Library,

    /// The Minecraft jar file
    Game,
}

/// Metadata associated with a [`Resource`]
pub struct ResourceMetadata<P>
where
    P: Provider,
{
    pub handle: P::ResourceHandle,
    pub name: String,
    pub description: String,
    //TODO(superwhiskers): how do we store the rest of this?
}

/// A trait representing a source of [`ResourceHandle`]s
///
/// Providers provide things such as layers and assets (referred to as "resources"). Since
/// instances are just collections of layers, there's no need to explicitly contain them
#[async_trait]
pub trait Provider: Sized {
    /// The kinds of [`Resource`]s that this [`Provider`] provides
    const PROVIDES: &'static [ResourceKind];

    /// An error that is encountered when a query fails
    type QueryError: Error;

    /// An error that is encountered when a fetch fails
    type FetchError: Error;

    /// The [`Stream`] used by the [`Provider::query`] method
    type QueryStream: Stream<Item = Result<(Self::ResourceHandle, ResourceMetadata<Self>), Self::QueryError>>
        + Send;

    /// A type representing a query that may be submitted to the underlying [`Provider`]
    type Query: From<Self::ResourceHandle>;

    /// A type representing a resource handle that may be either gotten from the [`Provider`] or known beforehand
    type ResourceHandle;

    /// Query a stream of [`ResourceHandle`]s from the [`Provider`] matching the provided query
    fn query(&self, query: impl Into<Self::Query>) -> Self::QueryStream;

    /// A variant of [`Provider::query`] which yields a single resource handle maximum
    async fn query_one(
        &self,
        query: impl Into<Self::Query> + Send,
    ) -> Result<Option<(Self::ResourceHandle, ResourceMetadata<Self>)>, Self::QueryError> {
        Box::pin(self.query(query)).try_next().await
    }
}

pub trait Resource<P>: AsyncRead
where
    P: Provider,
{
}
