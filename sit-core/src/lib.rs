//! sit-core is a library that implements SIT (SIT's an Issue Tracker)
//!
//! It is used by `sit` tooling and can be used by other projects to
//! build scripts or additional tooling for SIT.
//!
//! The main entry point to this library is [`Repository`] structure.
//!
//! [`Repository`]: repository/struct.Repository.html

#[macro_use] extern crate derive_error;
#[macro_use] extern crate typed_builder;

// Serialization
extern crate serde;
#[macro_use] extern crate serde_derive;
pub extern crate serde_json;

extern crate tempdir;
extern crate glob;
extern crate data_encoding;
#[macro_use] extern crate data_encoding_macro;
#[macro_use] extern crate lazy_static;

// Hashing
extern crate digest;
#[cfg(feature = "blake2")] extern crate blake2;
#[cfg(feature = "sha-1")] extern crate sha1;

#[cfg(feature = "uuid")] extern crate uuid;

#[cfg(feature = "memmap")] extern crate memmap;

#[cfg(feature = "cesu8")] extern crate cesu8;

#[cfg(feature = "git")] extern crate git2;

#[cfg(test)] extern crate dunce;

extern crate relative_path;

extern crate itertools;
extern crate walkdir;

// Crates necessary for testing
#[cfg(test)] #[macro_use] extern crate assert_matches;
#[cfg(test)] #[macro_use] extern crate proptest;


pub mod path;
pub mod hash;
pub mod encoding;
#[cfg(feature = "deprecated-item-api")]
pub mod id;
pub mod repository;
#[cfg(feature = "deprecated-item-api")]
pub mod item;
#[cfg(feature = "deprecated-item-api")]
pub use item::Item;
pub mod record;
pub use record::Record;
pub use repository::{Repository, Error as RepositoryError};
pub mod reducers;
pub use reducers::Reducer;
#[cfg(feature = "duktape")]
pub mod duktape;
pub mod cfg;
