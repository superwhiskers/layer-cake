use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
use kangarootwelve_xkcp::hash as k12_hash;
use rocksdb::{DBCompressionType, Error as RocksDBError, Options as DBOptions, DB};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::task;

use crate::resources::{Provider, Resource};

/// An SRI-formatted digest
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Sri {
    /// A KangarooTwelve message digest
    K12([u8; 32]),

    /// An MD5 message digest
    Md5([u8; 16]),

    /// An SHA-512 message digest
    Sha512([u8; 64]),

    /// An SHA-1 message digest
    Sha1([u8; 20]),
}

impl fmt::Display for Sri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sri::K12(digest) => {
                write!(f, "k12-{}", BASE64_STANDARD.encode(digest))
            }
            Sri::Md5(digest) => {
                write!(f, "md5-{}", BASE64_STANDARD.encode(digest))
            }
            Sri::Sha512(digest) => {
                write!(f, "sha512-{}", BASE64_STANDARD.encode(digest))
            }
            Sri::Sha1(digest) => {
                write!(f, "sha1-{}", BASE64_STANDARD.encode(digest))
            }
        }
    }
}

impl FromStr for Sri {
    type Err = base64::DecodeSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.split_once('-') {
            Some(("k12", digest)) => {
                let mut arr = [0; 32];
                BASE64_STANDARD.decode_slice(digest, &mut arr)?;

                Self::K12(arr)
            }
            Some(("md5", digest)) => {
                let mut arr = [0; 16];
                BASE64_STANDARD.decode_slice(digest, &mut arr)?;

                Self::Md5(arr)
            }
            Some(("sha512", digest)) => {
                let mut arr = [0; 64];
                BASE64_STANDARD.decode_slice(digest, &mut arr)?;

                Self::Sha512(arr)
            }
            Some(("sha1", digest)) => {
                let mut arr = [0; 20];
                BASE64_STANDARD.decode_slice(digest, &mut arr)?;

                Self::Sha1(arr)
            }

            //TODO(superwhiskers): consider using a more specific error
            Some(_) | None => Err(base64::DecodeSliceError::DecodeError(
                base64::DecodeError::InvalidLength,
            ))?,
        })
    }
}

/// The format of a config file
#[non_exhaustive]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ConfigFileFormat {
    /// Tom's Obvious Minimal Language
    ///
    /// More information can be found [here](https://toml.io)
    Toml,

    /// [JSON](https://json.org).
    ///
    /// Self-explanatory, hopefully
    Json,

    /// A Java [properties](https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/util/Properties.html#load(java.io.Reader)) file
    JavaProperties,

    /// The Minecraft [options.txt](https://minecraft.fandom.com/wiki/Options.txt) format
    ///
    /// This should only really be used for options.txt
    OptionsTxt,
}

/// The mod loader used by a mod
#[non_exhaustive]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ModLoader {
    /// The [Fabric](https://fabricmc.net/) mod loader
    Fabric,

    /// The [Quilt](https://quiltmc.org/) mod loader
    Quilt,
    //NOTE: forge may be supported at some point in the future. maybe more if there's a good
    //      enough reason to
}

/// General metadata for a [`Store`] item
#[derive(Serialize, Deserialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoreItemGeneralMetadata {
    pub file_name: String,
    pub particular: StoreItemParticularMetadata,
}

/// Particular metadata for a [`Store`] item
#[non_exhaustive]
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, Hash, PartialEq)]
pub enum StoreItemParticularMetadata {
    /// A mapping from one SRI digest to another (for dealing with external providers that
    /// don't exclusively use KangarooTwelve or whatever the client is configured for)
    Mapping(#[serde_as(as = "DisplayFromStr")] Sri),

    /// Metadata associated with a store item representing a configuration file
    ConfigFile {
        /// The format of configuration file
        ///
        /// Used when merging and diffing configuration files
        format: ConfigFileFormat,
    },

    /// Metadata associated with a mod file
    Mod {
        /// The mod loaders supported
        loader: Vec<ModLoader>,

        /// The name of the mod
        name: Option<String>,

        /// The version of the mod
        version: Option<String>,

        /// The homepage of the mod
        homepage: Option<String>,

        /// The contributor information for the mod
        contributors: Vec<String>,
    },

    /// Metadata associated with an auxiliary file
    Auxiliary,

    /// Metadata associated with a (java) library
    ///
    /// Native libraries are classified as auxiliary
    Library,

    /// Metadata associated with a Minecraft jar file
    Game {
        /// The version of the game
        version: String,
    },
}

#[derive(Debug)]
pub struct Store {
    directory: PathBuf,
    database: DB,
}

impl Store {
    /// Open a [`Store`] at the provided path, which must be a directory
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RocksDBError> {
        let path = path.as_ref();
        let mut db_options = DBOptions::default();
        db_options.set_compression_type(DBCompressionType::Zstd);

        Ok(Self {
            directory: path.to_path_buf(),
            database: DB::open(&db_options, path.join("index.db"))?,
        })
    }

    /*pub fn insert<P>(resource: impl Resource<P>) -> Result<(), !>
    where
        P: Provider,
    {
    }*/
}
