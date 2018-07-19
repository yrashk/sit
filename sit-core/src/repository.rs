//! Repository is where SIT stores all of its artifacts.
//!
//! It is represented by the [`Repository`] structure.
//!
//! [`Repository`]: struct.Repository.html
//!


use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;

use tempdir::TempDir;

use glob;

use serde_json;

use super::hash::HashingAlgorithm;
use super::encoding::Encoding;
use super::id::IdGenerator;

use std::collections::HashMap;

use std::marker::PhantomData;

/// Current repository format version
const VERSION: &str = "1";
/// Repository's config file name
const CONFIG_FILE: &str = "config.json";
/// Repository's issues path (deprecated)
const DEPRECATED_ISSUES_PATH: &str = "issues";
/// Repository's items path
const ITEMS_PATH: &str = "items";
/// Repository's modules path
const MODULES_PATH: &str = "modules";


/// Repository is the container for all SIT artifacts
#[derive(Debug, Clone)]
pub struct Repository<MI> {
    /// Path to the container
    path: PathBuf,
    /// Path to the config file. Mainly to avoid creating
    /// this path on demand for every operation that would
    /// require it
    config_path: PathBuf,
    /// Path to the modules. Mainly to avoid creating
    /// this path on demand for every operation that would
    /// require it
    modules_path: PathBuf,
    /// Path to items. Mainly to avoid creating this path
    /// on demand for every operation that would require it
    items_path: PathBuf,
    /// Configuration
    config: Config,
    /// Module iterator
    module_iterator: MI,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModuleDirectory<P: AsRef<Path>>(P);

pub trait ModuleIterator<P, E> {
    type Iter : Iterator<Item = Result<P, E>>;
    fn iter(&self) -> Result<Self::Iter, E>;
}

impl<P: AsRef<Path>> ModuleIterator<PathBuf, Error> for ModuleDirectory<P> {
    type Iter = ModuleDirectoryIterator;

    fn iter(&self) -> Result<Self::Iter, Error> {
        let path = self.0.as_ref();
        if !path.is_dir() {
            Ok(ModuleDirectoryIterator(None))
        } else {
            Ok(ModuleDirectoryIterator(Some(fs::read_dir(path)?)))
        }
    }
}

impl<T1, T2, P, E> ModuleIterator<P, E> for (T1, T2)
    where T1: ModuleIterator<P, E>, T2: ModuleIterator<P, E> {
    type Iter = ::std::iter::Chain<T1::Iter, T2::Iter>;

    fn iter(&self) -> Result<Self::Iter, E> {
        let t1 = self.0.iter()?;
        let t2 = self.1.iter()?;
        Ok(t1.chain(t2))
    }
}

pub struct ModuleDirectoryIterator(Option<fs::ReadDir>);

impl Iterator for ModuleDirectoryIterator {
    type Item = Result<PathBuf, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0 {
            None => None,
            Some(ref mut modules) => {
                match modules.next() {
                    None => None,
                    Some(Ok(f)) => {
                        let mut path = f.path();
                        if path.is_dir() {
                            Some(Ok(path))
                        } else {
                            Some(fs::File::open(&path)
                                .and_then(|mut f| {
                                    use std::io::Read;
                                    let mut s = String::new();
                                    f.read_to_string(&mut s).map(|_| s)
                                })
                                .and_then(|s| {
                                    #[cfg(windows)] {
                                        s = s.replace("/", "\\");
                                    }
                                    let trimmed_path = s.trim();
                                    path.pop(); // remove the file name
                                    Ok(path.join(PathBuf::from(trimmed_path)))
                                })
                                .map_err(|e| e.into()))
                        }
                    },
                    Some(Err(e)) => Some(Err(e.into())),
                }
            }
        }
    }
}

/// Repository configuration
#[derive(Debug, Clone, TypedBuilder, Serialize, Deserialize)]
pub struct Config {
     /// Hashing algorithm used
    hashing_algorithm: HashingAlgorithm,
    /// Encoding used
    encoding: Encoding,
    /// ID generator
    id_generator: IdGenerator,
    /// Repository version
    #[default = "String::from(VERSION)"]
    version: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl Config {
    /// Returns hashing algorithm
    pub fn hashing_algorithm(&self) -> &HashingAlgorithm {
        &self.hashing_algorithm
    }
    /// Returns encoding
    pub fn encoding(&self) -> &Encoding {
        &self.encoding
    }
    /// Returns extra configuration
    pub fn extra(&self) -> &HashMap<String, serde_json::Value> {
        &self.extra
    }
}

#[derive(PartialEq, Debug)]
pub enum Upgrade {
    IssuesToItems,
}

use std::fmt::{self, Display};

impl Display for Upgrade {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Upgrade::IssuesToItems => write!(f, "renaming issues/ to items/"),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    /// Item already exists
    AlreadyExists,
    /// Item not found
    NotFound,
    /// Path prefix error
    ///
    /// Currently, this is used when one attempts to create a record file outside of the record
    PathPrefixError,
    /// Upgrade required
    #[error(no_from, non_std)]
    UpgradeRequired(Upgrade),
    /// Invalid repository version
    #[error(no_from, non_std)]
    InvalidVersion {
        expected: String,
        got: String,
    },
    /// I/O error
    IoError(::std::io::Error),
    /// JSON (de)serialization error
    SerializationError(serde_json::Error),
    /// Base decoding error
    BaseDecodeError(::data_encoding::DecodeError),
}

#[allow(unused_variables,dead_code)]
mod default_files {
    include!(concat!(env!("OUT_DIR"), "/default_files.rs"));

    use std::path::PathBuf;
    use std::collections::HashMap;

    lazy_static! {
      pub static ref ASSETS: HashMap<PathBuf, File> = {
         let mut map = HashMap::new();
         let prefix = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("default-files");
         for entry in FILES.walk() {
            match entry {
               DirEntry::File(f) => {
                  let path = PathBuf::from(f.path().strip_prefix(&prefix).unwrap());
                  map.insert(path.clone(), f.clone());
               },
               _ => (),
            }
         }
         map
       };
    }

}

impl Repository<ModuleDirectory<PathBuf>> {
    /// Attempts creating a new repository. Fails with `Error::AlreadyExists`
    /// if a repository already exists.
    pub fn new<P: Into<PathBuf>>(path: P) -> Result<Self, Error> {
        Repository::new_with_config(path, Config {
            hashing_algorithm: Default::default(),
            encoding: Encoding::default(),
            id_generator: IdGenerator::default(),
            version: String::from(VERSION),
            extra: HashMap::new(),
        })
    }

    /// Attempts creating a new repository with a specified config. Fails with `Error::AlreadyExists`
    /// if a repository already exists.
    pub fn new_with_config<P: Into<PathBuf>>(path: P, config: Config) -> Result<Self, Error> {
        let path: PathBuf = path.into();
        if path.is_dir() && fs::read_dir(&path)?.next().is_some() {
            Err(Error::AlreadyExists)
        } else {
            let mut config_path = path.clone();
            config_path.push(CONFIG_FILE);
            let mut items_path = path.clone();
            items_path.push(ITEMS_PATH);
            fs::create_dir_all(&items_path)?;
            let modules_path = path.join(MODULES_PATH);
            let module_iterator = ModuleDirectory(modules_path.clone());
            let repo = Repository {
                path,
                config_path,
                items_path,
                config,
                modules_path,
                module_iterator,
            };
            repo.save()?;
            Ok(repo)
        }
    }

    /// Opens an existing repository. Fails if there's no valid repository at the
    /// given path
    pub fn open<P: Into<PathBuf>>(path: P) -> Result<Self, Error> {
        Repository::open_and_upgrade(path, &[])
    }

    /// Opens and, if necessary, upgrades an existing repository.
    /// Allow to specify which particular upgrades should be allowed.
    ///
    /// Fails if there's no valid repository at the
    /// given path.
    pub fn open_and_upgrade<P: Into<PathBuf>, U: AsRef<[Upgrade]>>(path: P, upgrades: U) -> Result<Self, Error> {
        let path: PathBuf = path.into();
        let mut config_path = path.clone();
        config_path.push(CONFIG_FILE);
        let issues_path = path.join(DEPRECATED_ISSUES_PATH);
        let items_path = path.join(ITEMS_PATH);
        let modules_path = path.join(MODULES_PATH);
        if issues_path.is_dir() && !items_path.is_dir() {
            if upgrades.as_ref().contains(&Upgrade::IssuesToItems) {
                fs::rename(&issues_path, &items_path)?;
            } else {
                return Err(Error::UpgradeRequired(Upgrade::IssuesToItems));
            }
        }
        if issues_path.is_dir() && items_path.is_dir() {
            if upgrades.as_ref().contains(&Upgrade::IssuesToItems) {
                for item in fs::read_dir(&issues_path)?.filter(Result::is_ok).map(Result::unwrap) {
                    fs::rename(item.path(), items_path.join(item.file_name()))?;
                }
                fs::remove_dir_all(&issues_path)?;
            } else {
                return Err(Error::UpgradeRequired(Upgrade::IssuesToItems));
            }
        }
        // dropping issues_path so it can no longer be used
        // by mistake
        drop(issues_path);
        fs::create_dir_all(&items_path)?;
        let file = fs::File::open(&config_path)?;
        let config: Config = serde_json::from_reader(file)?;
        if config.version != VERSION {
            return Err(Error::InvalidVersion { expected: String::from(VERSION), got: config.version });
        }
        let module_iterator = ModuleDirectory(modules_path.clone());
        let repository = Repository {
            path,
            config_path,
            items_path,
            config,
            modules_path,
            module_iterator,
        };
        Ok(repository)
    }

    /// Finds SIT repository in `path` or any of its parent directories, or within the same
    /// hierarchy under a sub-directory `dir` (often `".sit"` by convention)
    pub fn find_in_or_above<P: Into<PathBuf>, S: AsRef<str>>(dir: S, path: P) -> Option<PathBuf> {
        let mut path: PathBuf = path.into();
        let dir = dir.as_ref();
        path.push(dir);
        loop {
            match path.parent() {
                Some(parent) if Repository::open(&parent).is_ok() => return Some(parent.into()),
                _ => (),
            }
            if !path.is_dir() {
                // get out of `dir`
                path.pop();
                // if can't pop anymore, we're at the root of the filesystem
                if !path.pop() {
                    return None
                }
                // try assuming current path + `dir`
                path.push(dir);
            } else {
                if Repository::open(&path).is_ok() {
                    break;
                } else {
                    return None;
                }
            }
        }
        Some(path)
    }

}

impl<MI> Repository<MI> {

    /// Returns a new instance of Repository with an additional module iterator
    /// chained to the existing one
    pub fn with_module_iterator<MI1>(self, module_iterator: MI1) -> Repository<(MI, MI1)> {
        Repository {
            path: self.path,
            config_path: self.config_path,
            modules_path: self.modules_path,
            items_path: self.items_path,
            config: self.config,
            module_iterator: (self.module_iterator, module_iterator),
        }
    }

    /// Saves the repository. Ensures the directory exists and the configuration has
    /// been saved.
    fn save(&self) -> Result<(), Error> {
        fs::create_dir_all(&self.path)?;
        let file = fs::File::create(&self.config_path)?;
        serde_json::to_writer_pretty(file, &self.config)?;
        Ok(())
    }

    /// Populates repository with default files
    pub fn populate_default_files(&self) -> Result<(), Error> {
        for (name, file) in default_files::ASSETS.iter() {
            let mut dir = self.path.join(name);
            dir.pop();
            fs::create_dir_all(dir)?;
            let mut f = fs::File::create(self.path.join(name))?;
            f.write(file.contents)?;
        }
        Ok(())
    }

    /// Returns repository path
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns items path
    pub fn items_path(&self) -> &Path {
        self.items_path.as_path()
    }

    /// Returns repository's config
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns an unordered (as in "order not defined") item iterator
    pub fn item_iter(&self) -> Result<ItemIter<MI>, Error> {
        Ok(ItemIter { repository: self, dir: fs::read_dir(&self.items_path)? })
    }

    /// Creates and returns a new item with a unique ID
    pub fn new_item(&self) -> Result<Item<MI>, Error> {
        self.new_named_item(self.config.id_generator.generate())
    }

    /// Creates and returns a new item with a specific name. Will fail
    /// if there's an item with the same name.
    pub fn new_named_item<S: Into<String>>(&self, name: S) -> Result<Item<MI>, Error> {
        let id: String = name.into();
        let mut path = self.items_path.clone();
        path.push(&id);
        fs::create_dir(path)?;
        let id = OsString::from(id);
        Ok(Item {
            repository: self,
            id,
        })
    }

    /// Finds an item by name (if there is one)
    pub fn item<S: AsRef<str>>(&self, name: S) -> Option<Item<MI>> {
        let path = self.items_path().join(name.as_ref());
        if path.is_dir() && path.strip_prefix(self.items_path()).is_ok() {
            let mut test = path.clone();
            test.pop();
            if test != self.items_path() {
                return None;
            }
            let id = path.file_name().unwrap().to_os_string();
            let item = Item { repository: self, id };
            Some(item)
        } else {
            None
        }
    }

    /// Returns path to modules. The target directory may not exist.
    pub fn modules_path(&self) -> &Path {
        &self.modules_path
    }
}

impl<MI> Repository<MI> where MI: ModuleIterator<PathBuf, Error>
{
    /// Returns an iterator over the list of modules (directories under `modules` directory)
    pub fn module_iter<'a>(&'a self) -> Result<MI::Iter, Error> {
        let iter = self.module_iterator.iter()?;
        Ok(iter)
    }
}

impl<MI> PartialEq for Repository<MI> {
    fn eq(&self, rhs: &Repository<MI>) -> bool {
        (self as *const Repository<MI>) == (rhs as *const Repository<MI>)
    }
}

use super::Item as ItemTrait;

use std::ffi::OsString;

/// An item residing in a repository
#[derive(Debug, PartialEq)]
pub struct Item<'a, MI: 'a> {
    repository: &'a Repository<MI>,
    id: OsString,
}

use record::{File, OrderedFiles};
use relative_path::{RelativePath, Component as RelativeComponent};

impl<'a, MI: 'a> Item<'a, MI> {
    pub fn new_record_in<'f, P: AsRef<Path>, F: File + 'f, I: Into<OrderedFiles<'f, F>>>(&self, path: P, files: I, link_parents: bool) ->
           Result<<Item<'a, MI> as ItemTrait>::Record, <Item<'a, MI> as ItemTrait>::Error> where F::Read: 'f {
        let tempdir = TempDir::new_in(&self.repository.path,"sit")?;
        let mut hasher = self.repository.config.hashing_algorithm.hasher();

        let files: OrderedFiles<F> = files.into();

        // Link parents if requested
        let files = if link_parents {
            let records = self.record_iter()?.last().unwrap_or(vec![]);
            let parents: OrderedFiles<_> = records.iter().map(|rec| (format!(".prev/{}", rec.encoded_hash()), &b""[..])).into();
            files + parents
        } else {
            files.boxed()
        };

        files.hash_and(&mut *hasher, |n| -> Result<fs::File, Error> {
            let path = RelativePath::new(n).normalize();
            if path.components().any(|c| match c {
                RelativeComponent::Normal(_) => false,
                _ => true,
            }) {
                return Err(Error::PathPrefixError);
            }
            let actual_path = path.to_path(tempdir.path());
            let mut dir = actual_path.clone();
            dir.pop();
            fs::create_dir_all(dir)?;
            let file = fs::File::create(actual_path)?;
            Ok(file)
        }, |mut f, c| -> Result<fs::File, Error> { f.write(c).map(|_| f).map_err(|e| e.into()) })?;


        let hash = hasher.result_box();
        let path = path.as_ref().join(PathBuf::from(self.repository.config.encoding.encode(&hash)));
        fs::rename(tempdir.into_path(), &path)?;
        Ok(Record {
            hash,
            item: self.id.clone(),
            repository: self.repository,
            path,
        })
    }

}
impl<'a, MI: 'a> ItemTrait for Item<'a, MI> {

    type Error = Error;
    type Record = Record<'a, MI>;
    type Records = Vec<Record<'a, MI>>;
    type RecordIter = ItemRecordIter<'a, MI>;

    fn id(&self) -> &str {
        self.id.to_str().unwrap()
    }

    fn record_iter(&self) -> Result<Self::RecordIter, Self::Error> {
        let path = self.repository.items_path.join(PathBuf::from(&self.id()));
        let dir = fs::read_dir(&path)?.filter(|r| r.is_ok())
            .map(|e| e.unwrap())
            .collect();
        Ok(ItemRecordIter {
            item: self.id.clone(),
            repository: self.repository,
            dir,
            parents: vec![],
        })
    }

    fn new_record<'f, F: File + 'f, I: Into<OrderedFiles<'f, F>>>(&self, files: I, link_parents: bool) -> Result<Self::Record, Self::Error> where F::Read: 'f {
       self.new_record_in(self.repository.items_path.join(PathBuf::from(self.id())), files, link_parents)
    }

}

/// An iterator over records in an item
pub struct ItemRecordIter<'a, MI: 'a> {
    item: OsString,
    repository: &'a Repository<MI>,
    dir: Vec<fs::DirEntry>,
    parents: Vec<String>,
}

impl<'a, MI: 'a> Iterator for ItemRecordIter<'a, MI> {
    type Item = Vec<Record<'a, MI>>;

    fn next(&mut self) -> Option<Self::Item> {
        let item_path = self.repository.items_path.join(&self.item);
        // TODO: if https://github.com/rust-lang/rust/issues/43244 is finalized, try to use drain_filter instead
        let (filtered, dir): (Vec<_>, Vec<_>) = ::std::mem::replace(&mut self.dir, vec![]).into_iter()
            .partition(|e| {
                if !e.file_type().unwrap().is_dir() {
                    return false
                }
                let valid_name = self.repository.config.encoding.decode(e.file_name().to_str().unwrap().as_bytes()).is_ok();
                if !valid_name {
                    return false;
                }

                let dot_prev = e.path().join(".prev");
                let has_all_valid_parents = !dot_prev.is_dir() || match fs::read_dir(dot_prev) {
                    Err(_) => false,
                    Ok(dir) => {
                        dir.filter_map(Result::ok)
                            // only use links pointing to actual directories
                            .filter(|l| item_path.join(l.file_name()).is_dir())
                            // has to be already processed
                            .all(|l| self.parents.iter().any(|p| p.as_str() == l.file_name().to_str().unwrap()))

                    }
                };
                has_all_valid_parents
            });
        let result: Vec<_> = filtered.iter()
            .map(|e| Record {
                hash: self.repository.config.encoding.decode(e.file_name().to_str().unwrap().as_bytes()).unwrap(),
                item: self.item.clone(),
                repository: self.repository,
                path: item_path.join(e.file_name()),
            })
            .collect();
        self.dir = dir;
        if result.len() == 0 {
            return None
        }
        self.parents.append(&mut result.iter().map(|r| r.encoded_hash()).collect());
        Some(result)
    }
}


/// Unordered (as in "order not defined') item iterator
/// within a repository
pub struct ItemIter<'a, MI: 'a> {
    repository: &'a Repository<MI>,
    dir: fs::ReadDir,
}

impl<'a, MI: 'a> Iterator for ItemIter<'a, MI> {
    type Item = Item<'a, MI>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.dir.next() {
                None => return None,
                // bail on an entry if the entry is erroneous
                Some(Err(_)) => continue,
                Some(Ok(entry)) => {
                    let file_type = entry.file_type();
                    // bail on an entry if checking for the file type
                    // resulted in an error
                    if file_type.is_err() {
                        continue;
                    }
                    let file_type = file_type.unwrap();
                    if file_type.is_dir() {
                        return Some(Item { repository: self.repository, id: entry.file_name() });
                    } else {
                        continue;
                    }
                }
            }
        }
    }
}

use super::Record as RecordTrait;

/// A record within an item
#[derive(Debug)]
pub struct Record<'a, MI: 'a> {
    hash: Vec<u8>,
    item: OsString,
    repository: &'a Repository<MI>,
    path: PathBuf,
}

impl<'a, MI: 'a> Record<'a, MI> {

    /// Returns path to the record
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

}


use serde::{Serialize, Serializer};

impl<'a, MI: 'a> Serialize for Record<'a, MI> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        use record::RecordExt;
        self.serde_serialize(serializer)
    }
}


impl<'a, MI: 'a> PartialEq for Record<'a, MI> {
   fn eq(&self, other: &Record<'a, MI>) -> bool {
       self.hash == other.hash
   }
}

impl<'a, MI: 'a> RecordTrait for Record<'a, MI> {
    type Read = ::std::fs::File;
    type Str = String;
    type Hash = Vec<u8>;
    type Iter = RecordFileIterator<'a>;

    fn hash(&self) -> Self::Hash {
        self.hash.clone()
    }

    fn encoded_hash(&self) -> Self::Str {
        self.repository.config.encoding.encode(&self.hash)
    }

    fn file_iter(&self) -> Self::Iter {
        let path = self.path();
        let glob_pattern = format!("{}/**/*", path.to_str().unwrap());
        RecordFileIterator {
            glob: glob::glob(&glob_pattern).expect("invalid glob pattern"),
            prefix: self.path().into(),
            phantom: PhantomData,
        }
    }
    fn item_id(&self) -> Self::Str {
        self.item.clone().into_string().unwrap()
    }
}

/// An iterator over files in a record
pub struct RecordFileIterator<'a> {
    glob: glob::Paths,
    prefix: PathBuf,
    phantom: PhantomData<&'a ()>,
}

impl<'a> Iterator for RecordFileIterator<'a> {
    type Item = (String, fs::File);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.glob.next() {
                None => return None,
                // skip on errors
                Some(Err(_)) => continue,
                Some(Ok(name)) => {
                    if name.is_file() {
                        let stripped = String::from(name.strip_prefix(&self.prefix).unwrap().to_str().unwrap());
                        #[cfg(windows)] // replace backslashes with slashes
                        let stripped = stripped.replace("\\", "/");
                        return Some((stripped, fs::File::open(name).unwrap()))
                    } else {
                        // if it is not a file, keep iterating
                        continue
                    }
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {

    use tempdir::TempDir;

    use super::*;

    #[test]
    fn new_repo() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        assert_eq!(repo.item_iter().unwrap().count(), 0); // no items in a new repo
        assert_eq!(repo.path(), tmp);
    }

    #[test]
    fn new_repo_already_exists() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let _repo = Repository::new(&tmp).unwrap();
        // try creating it again
        let repo = Repository::new(&tmp);
        assert!(repo.is_err());
        assert_matches!(repo.unwrap_err(), Error::AlreadyExists);
    }

    #[test]
    fn open_repo() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        let repo = Repository::open(&tmp).unwrap();
        // load items
        let mut items: Vec<Item<_>> = repo.item_iter().unwrap().collect();
        assert_eq!(items.len(), 1);
        // check equality of the item's ID
        assert_eq!(items.pop().unwrap().id(), item.id());
    }

    #[test]
    fn find_repo() {
        let tmp = TempDir::new("sit").unwrap().into_path();
        let sit = tmp.join(".sit");
        // create repo
        Repository::new(&sit).unwrap();
        let deep_subdir = tmp.join("a/b/c/d");
        let repo = Repository::find_in_or_above(".sit", &deep_subdir);
        assert!(repo.is_some());
        let repo = Repository::open(repo.unwrap()).unwrap();
        assert_eq!(repo.path(), sit);
        // negative test
        assert!(Repository::find_in_or_above(".sit-dir", &deep_subdir).is_none());
        // non-repo shouldn't be found
        let tmp1 = TempDir::new("sit").unwrap().into_path() ;
        let non_sit = tmp1.join(".sit");
        fs::create_dir_all(non_sit).unwrap();
        let deep_subdir = tmp1.join("a/b/c/d");
        assert!(Repository::find_in_or_above(".sit", &deep_subdir).is_none());
    }


    #[test]
    fn find_repo_in_itself() {
        // unlike `find_repo`, this tests whether we can find a repository
        // that is not contained in a `.sit` folder
        let sit = TempDir::new("sit").unwrap().into_path();
        // create repo
        Repository::new(&sit).unwrap();
        let subdir = sit.join("items");
        let repo = Repository::find_in_or_above(".sit", &subdir);
        assert!(repo.is_some());
        let repo = Repository::open(repo.unwrap()).unwrap();
        assert_eq!(repo.path(), sit);
    }


    #[test]
    fn new_item() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // load items
        let mut items: Vec<Item<_>> = repo.item_iter().unwrap().collect();
        assert_eq!(items.len(), 1);
        // check equality of the item's ID
        assert_eq!(items.pop().unwrap().id(), item.id());
    }

    #[test]
    fn new_named_item() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_named_item("one").unwrap();
        // load items
        let mut items: Vec<Item<_>> = repo.item_iter().unwrap().collect();
        assert_eq!(items.len(), 1);
        // check equality of the item's ID
        assert_eq!(items.pop().unwrap().id(), item.id());
    }

    #[test]
    fn new_named_item_dup() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let _item = repo.new_named_item("one").unwrap();
        // attempt to use the same name
        let item1 = repo.new_named_item("one");
        assert!(item1.is_err());
        assert_matches!(item1.unwrap_err(), Error::IoError(_));
        // there's still just one item
        assert_eq!(repo.item_iter().unwrap().count(), 1);
    }

    #[test]
    fn find_item() {
         let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_named_item("one").unwrap();
       // find an existing item
        assert_eq!(repo.item("one").unwrap(), item);
        // find a non-existing item
        assert!(repo.item("two").is_none());
        // point outside of items
        assert!(repo.item("/").is_none());
        // point anywhere not one level below items
        assert!(repo.item("one/..").is_none());
        item.new_record(vec![("test/it", &[1u8][..])].into_iter(), false).unwrap();
        assert!(repo.item("one/it").is_none());
    }

    #[test]
    fn new_record() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // create a record
        let record = item.new_record(vec![("test", &b"hello"[..])].into_iter(), true).unwrap();
        // peek into the record
        let mut files: Vec<_> = record.file_iter().collect();
        assert_eq!(files.len(), 1);
        let (name, mut file) = files.pop().unwrap();
        assert_eq!(name, "test");
        use std::io::Read;
        let mut string = String::new();
        assert!(file.read_to_string(&mut string).is_ok());
        assert_eq!(string, "hello");
        // list records
        let mut records: Vec<Record<_>> = item.record_iter().unwrap().flat_map(|v| v).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records.pop().unwrap().hash(), record.hash());
    }

    #[test]
    fn record_files_path() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // attempt to create a record with an invalid filename
        assert_matches!(item.new_record(vec![(".", &b"hello"[..])].into_iter(), false), Err(Error::IoError(_)));
        assert_matches!(item.new_record(vec![("../test", &b"hello"[..])].into_iter(), false), Err(Error::PathPrefixError));
        assert_matches!(item.new_record(vec![("something/../../test", &b"hello"[..])].into_iter(), false), Err(Error::PathPrefixError));
        // however, these are alright
        assert_matches!(item.new_record(vec![("something/../test", &b"hello"[..])].into_iter(), false), Ok(_));
        assert_matches!(item.new_record(vec![("./test1", &b"hello"[..])].into_iter(), false), Ok(_));
        // root is normalized, too
        let record = item.new_record(vec![("/test2", &b"hello"[..])].into_iter(), false).unwrap();
        assert_eq!(record.file_iter().next().unwrap().name(), "test2");
    }


    #[test]
    fn new_record_parents_linking() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // create a few top records
        let record1 = item.new_record(vec![("test", &[1u8][..])].into_iter(), false).unwrap();
        let record1link = format!(".prev/{}", record1.encoded_hash());
        let record2 = item.new_record(vec![("test", &[2u8][..])].into_iter(), false).unwrap();
        let record2link = format!(".prev/{}", record2.encoded_hash());
        // now attempt to create a record that should link both together
        let record = item.new_record(vec![("test", &[3u8][..])].into_iter(), true).unwrap();
        assert!(record.file_iter().any(|(name, _)| name == *&record1link));
        assert!(record.file_iter().any(|(name, _)| name == *&record2link));
    }

    #[test]
    fn record_ordering() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // create a few top records
        let record1 = item.new_record(vec![("test", &[1u8][..])].into_iter(), false).unwrap();
        let record2 = item.new_record(vec![("test", &[2u8][..])].into_iter(), false).unwrap();
        // now attempt to create a record that should link both together
        let record3 = item.new_record(vec![("test", &[3u8][..])].into_iter(), true).unwrap();
        // and another top record
        let record4 = item.new_record(vec![("test", &[4u8][..])].into_iter(), false).unwrap();
        // and another linking record
        let record5 = item.new_record(vec![("test", &[5u8][..])].into_iter(), true).unwrap();

        // now, look at their ordering
        let mut records: Vec<_> = item.record_iter().unwrap().collect();
        let row_3 = records.pop().unwrap();
        let row_2 = records.pop().unwrap();
        let row_1 = records.pop().unwrap();
        assert_eq!(records.len(), 0);

        assert_eq!(row_1.len(), 3);
        assert!(row_1.iter().any(|r| r == &record1));
        assert!(row_1.iter().any(|r| r == &record2));
        assert!(row_1.iter().any(|r| r == &record4));

        assert_eq!(row_2.len(), 1);
        assert!(row_2.iter().any(|r| r == &record3));

        assert_eq!(row_3.len(), 1);
        assert!(row_3.iter().any(|r| r == &record5));
    }

    #[test]
    fn multilevel_parents() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        // create an item
        let item = repo.new_item().unwrap();
        // create a top record
        let record1 = item.new_record(vec![("test", &[1u8][..])].into_iter(), false).unwrap();
        // create a record right below it
        let record2 = item.new_record(vec![("test", &[2u8][..])].into_iter(), true).unwrap();
        // now attempt to create a record that should link both together
        let record3 = item.new_record(vec![("test", &[3u8][..]),
                                           (&format!(".prev/{}", record1.encoded_hash()), &[][..]),
                                           (&format!(".prev/{}", record2.encoded_hash()), &[][..]),
        ].into_iter(), false).unwrap();

        // now, look at their ordering
        let mut records: Vec<_> = item.record_iter().unwrap().collect();
        let row_3 = records.pop().unwrap();
        let row_2 = records.pop().unwrap();
        let row_1 = records.pop().unwrap();
        assert_eq!(records.len(), 0);

        assert_eq!(row_1.len(), 1);
        assert!(row_1.iter().any(|r| r == &record1));

        assert_eq!(row_2.len(), 1);
        assert!(row_2.iter().any(|r| r == &record2));

        assert_eq!(row_3.len(), 1);
        assert!(row_3.iter().any(|r| r == &record3));
    }


    #[test]
    fn partial_ordering() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");

        // first repo
        let repo1 = Repository::new(&tmp).unwrap();
        // create an item
        let item1 = repo1.new_item().unwrap();
        // create a few top records
        let _record0 = item1.new_record(vec![("test", &[2u8][..])].into_iter(), false).unwrap();
        // this record will link only to one top record
        let record1 = item1.new_record(vec![("test", &[3u8][..])].into_iter(), true).unwrap();
        let record2 = item1.new_record(vec![("test", &[1u8][..])].into_iter(), false).unwrap();
        // now attempt to create a record that should link both together
        let record3 = item1.new_record(vec![("test", &[3u8][..])].into_iter(), true).unwrap();


        let mut tmp1 = TempDir::new("sit").unwrap().into_path();
        tmp1.push(".sit");

        // second repo
        let repo2 = Repository::new(&tmp1).unwrap();
        // create an item
        let item2 = repo2.new_item().unwrap();
        // replicate one of the top records only
        let record2_2 = item2.new_record(record2.file_iter(), false).unwrap();

        // now copy record3 that linked both top records in the first repo
        // to the second repo
        let record3_2 = item2.new_record(record3.file_iter(), false).unwrap();
        // ensure their hashes match
        assert_eq!(record3_2.hash(), record3.hash());

        // now copy record1 that linked both top records in the first repo
        // to the second repo
        let record1_2 = item2.new_record(record1.file_iter(), false).unwrap();
        // ensure their hashes match
        assert_eq!(record1_2.hash(), record1.hash());

        // now, look at the records in the second item
        let mut records: Vec<_> = item2.record_iter().unwrap().collect();
        let row_2 = records.pop().unwrap();
        let row_1 = records.pop().unwrap();
        assert_eq!(records.len(), 0);

        // ensure the partially resolvable record to be there
        assert_eq!(row_2.len(), 1);
        assert!(row_2.iter().any(|r| r == &record3_2));

        assert_eq!(row_1.len(), 2);
        // as well as one of its parents
        assert!(row_1.iter().any(|r| r == &record2_2));
        // as well as the one that has no resolvable parents
        assert!(row_1.iter().any(|r| r == &record1_2));
    }

    #[test]
    fn record_deterministic_hashing() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let repo = Repository::new(&tmp).unwrap();
        let item1 = repo.new_item().unwrap();
        let record1 = item1.new_record(vec![("z/a", &[2u8][..]), ("test", &[1u8][..])].into_iter(), false).unwrap();
        let item2 = repo.new_item().unwrap();
        let record2 = item2.new_record(vec![("test", &[1u8][..]), ("z/a", &[2u8][..])].into_iter(), false).unwrap();
        assert_eq!(record1.hash(), record2.hash());
        let item3 = repo.new_item().unwrap();
        let record3 = item3.new_record(vec![("test", &[1u8][..]), ("z\\a", &[2u8][..])].into_iter(), false).unwrap();
        assert_eq!(record3.hash(), record2.hash());
    }

    #[test]
    fn record_outside_naming_scheme() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let mut tmp1 = tmp.clone();
        tmp1.pop();

        let repo = Repository::new(&tmp).unwrap();
        let item = repo.new_item().unwrap();
        let _record1 = item.new_record(vec![("z/a", &[2u8][..]), ("test", &[1u8][..])].into_iter(), false).unwrap();
        let record2 = item.new_record_in(&tmp1, vec![("a", &[2u8][..])].into_iter(), true).unwrap();

        // lets test that record2 can iterate over correct files
        let files: Vec<_> = record2.file_iter().collect();
        assert_eq!(files.len(), 2); // a and .prev/...


        // record2 can't be found as it is outside of the standard naming scheme
        let records: Vec<Vec<_>> = item.record_iter().unwrap().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 1);

        // On Windows, if a file within a directory that is being
        // moved is open (even for reading), this will prevent
        // this said directory from being moved, returning "Access Denied"
        // Therefore, we drop `files` here to release the `File` readers
        #[cfg(windows)]
        drop(files);

        ::std::fs::rename(record2.path(), repo.items_path().join(item.id()).join(record2.encoded_hash())).unwrap();

        // and now it can be
        let records: Vec<Vec<_>> = item.record_iter().unwrap().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].len(), 1);
        assert_eq!(records[0].len(), 1);

    }

    #[test]
    fn issues_to_items_upgrade() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let mut tmp1 = tmp.clone();
        tmp1.pop();

        let repo = Repository::new(&tmp).unwrap();
        let _item = repo.new_item().unwrap();
        assert_eq!(repo.item_iter().unwrap().count(), 1);

        ::std::fs::rename(repo.items_path(), repo.path().join("issues")).unwrap();
        let repo = Repository::open(&tmp);
        assert!(repo.is_err());
        assert_matches!(repo.unwrap_err(), Error::UpgradeRequired(Upgrade::IssuesToItems));

        let repo = Repository::open_and_upgrade(&tmp, &[Upgrade::IssuesToItems]).unwrap();
        assert!(!repo.path().join("issues").exists());
        assert_eq!(repo.item_iter().unwrap().count(), 1);

        // now, a more complicated case:
        // both issues/ and items/ are present
        // this can happen when merging a patch that changes .sit/issues
        // (prepared before the migration)
        let item = repo.new_item().unwrap();
        ::std::fs::create_dir_all(repo.path().join("issues")).unwrap();
        ::std::fs::rename(repo.items_path().join(item.id()), repo.path().join("issues").join(item.id())).unwrap();

        let repo = Repository::open(&tmp);
        assert!(repo.is_err());
        assert_matches!(repo.unwrap_err(), Error::UpgradeRequired(Upgrade::IssuesToItems));

        let repo = Repository::open_and_upgrade(&tmp, &[Upgrade::IssuesToItems]).unwrap();
        assert!(!repo.path().join("issues").exists());
        assert_eq!(repo.item_iter().unwrap().count(), 2);

    }

    #[test]
    fn modules() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let mut tmp1 = tmp.clone();
        tmp1.pop();

        let repo = Repository::new(&tmp).unwrap();
        assert!(repo.module_iter().unwrap().next().is_none());

        // create modules/test
        let path = repo.modules_path().join("test");
        fs::create_dir_all(&path).unwrap();
        let mut iter = repo.module_iter().unwrap();

        assert_eq!(::dunce::canonicalize(iter.next().unwrap().unwrap()).unwrap(), ::dunce::canonicalize(path).unwrap());
        assert!(iter.next().is_none());
    }

    #[test]
    fn link_module_absolute() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let mut tmp1 = tmp.clone();
        tmp1.pop();

        let tmp2 = TempDir::new("sit-mod").unwrap().into_path();

        let repo = Repository::new(&tmp).unwrap();
        assert!(repo.module_iter().unwrap().next().is_none());

        // create modules/test
        fs::create_dir_all(repo.modules_path()).unwrap();
        let mut f = fs::File::create(repo.modules_path().join("test")).unwrap();
        f.write(tmp2.to_str().unwrap().as_bytes()).unwrap();

        let mut iter = repo.module_iter().unwrap();

        assert_eq!(iter.next().unwrap().unwrap(), tmp2);
        assert!(iter.next().is_none());
    }

    #[test]
    fn link_module_relative() {
        let mut tmp = TempDir::new("sit").unwrap().into_path();
        tmp.push(".sit");
        let mut tmp1 = tmp.clone();
        tmp1.pop();



        let repo = Repository::new(&tmp).unwrap();
        fs::create_dir_all(tmp.join("module1")).unwrap();

        assert!(repo.module_iter().unwrap().next().is_none());

        // create modules/test
        fs::create_dir_all(repo.modules_path()).unwrap();
        let mut f = fs::File::create(repo.modules_path().join("test")).unwrap();
        f.write(b"../module1").unwrap();

        let mut iter = repo.module_iter().unwrap();

        assert_eq!(::dunce::canonicalize(iter.next().unwrap().unwrap()).unwrap(), ::dunce::canonicalize(tmp.join("module1")).unwrap());
        assert!(iter.next().is_none());
    }



}

