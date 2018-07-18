use cli;
use std::path::{Path, PathBuf};
use sit_core;

pub struct ScriptModule<MI, P: AsRef<Path>>(pub sit_core::Repository<MI>, pub P, pub String);
use sit_core::repository::{Error as RepositoryError, ModuleIterator};

use std::io::{Lines, BufRead, Cursor};

impl<MI, P: AsRef<Path>> ModuleIterator<PathBuf, RepositoryError> for ScriptModule< MI, P>
    where MI: sit_core::repository::ModuleIterator<PathBuf, sit_core::repository::Error> {
    type Iter = ScriptModuleIterator;

    fn iter(&self) -> Result<Self::Iter, RepositoryError> {
        cli::execute_cli(&self.0, self.1.as_ref(), self.2.as_str(), vec!["list".into()], true)
            .map(|(_, out)| ScriptModuleIterator(Cursor::new(out).lines()))
            .map_err(|_| RepositoryError::NotFound) // FIXME (temp)
    }
}

pub struct ScriptModuleIterator(Lines<Cursor<Vec<u8>>>);

impl Iterator for ScriptModuleIterator {
    type Item = Result<PathBuf, RepositoryError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|s|
            s.map(|s_| PathBuf::from(s_))
            .map_err(|e| e.into()))
    }

}
