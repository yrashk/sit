use std::path::{Path, PathBuf};
use std::env;
use clap::ArgMatches;
use sit_core::{self, Repository};

use crate::cli::{execute_cli, Error};

pub fn command<MI>(matches: &ArgMatches, repo: Repository<MI>, cwd: &Path) -> Result<i32, Error>
    where MI: sit_core::repository::ModuleIterator<PathBuf, sit_core::repository::Error> {
    let (subcommand, args) = matches.subcommand();
    let var = env::var("SIT_SUBCOMMAND");
    if var.is_ok() && var.unwrap() == subcommand {
        return Err(Error::WhichError);
    } else {
        let args = args.and_then(|args| args.values_of_lossy("")).unwrap_or(vec![]);
    return execute_cli::<_,_, &str, &str>(&repo, cwd, subcommand, args, None, false).map(|(code, _)| code);
    }

}
