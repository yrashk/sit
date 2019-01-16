#[cfg(feature = "git")]
use git2;
use std::env;
use std::io;
use std::path::PathBuf;
use std::thread;

use clap::ArgMatches;
use directories::ProjectDirs;

use sit_core::{self, repository, Repository, record::RecordContainerReduction};
use crate::cfg::Configuration;
use pbr;

use serde_json;

enum ExitError {
    CantDeriveDirs,
    GitError(git2::Error),
    IoError(io::Error),
    Failure(String),
}

use std;
use std::fmt;
impl fmt::Debug for ExitError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        match self {
            ExitError::CantDeriveDirs => write!(fmt, "Can't derive directories"),
            ExitError::GitError(err) => write!(fmt, "Git error: {:?}", err),
            ExitError::IoError(err) => write!(fmt, "I/O error: {:?}", err),
            ExitError::Failure(err) => write!(fmt, "{}", err),
        }
    }
}

impl From<git2::Error> for ExitError {
    fn from(err: git2::Error) -> Self {
        ExitError::GitError(err)
    }
}

impl From<io::Error> for ExitError {
    fn from(err: io::Error) -> Self {
        ExitError::IoError(err)
    }
}

const DEFAULT_MODULE_REPOSITORY_URL: &str = "git+https://git.sit.fyi/modules";

fn cross_host_enabled_git_operation<F, T>(mut f: F, url: &str) -> Result<T, git2::Error>
where
    F: FnMut(&str) -> Result<T, git2::Error>,
{
    use cabot::{Client, RequestBuilder};
    f(url).or_else(|e| {
        if e.message() == "cross host redirect not allowed" {
            let client = Client::new();
            RequestBuilder::new(url).build()
            .map_err(|_| git2::Error::from_str("error building request"))
            .and_then(move |r| client.execute(&r)
                .map_err(|_| e)) // if it fails, revert to the old error
            .map(|r| {
                for header in r.headers() {
                    if header.starts_with("Location: ") {
                        return String::from(&header[10..])
                    }
                }
                url.into()
            })
            .and_then(|url_| f(url_.as_str()))
        } else {
            Err(e)
        }
    })
}

pub fn command<MI>(repo: Repository<MI>, matches: &ArgMatches, cfg: Configuration, cwd: PathBuf) -> i32
    where MI: repository::ModuleIterator<PathBuf, repository::Error> {
    match command_(repo, matches, cfg, cwd) {
        Ok(()) => 0,
        Err(err) => {
            println!("{:?}", err);
            1
        }
    }
}

fn command_<MI>(repo: Repository<MI>, matches: &ArgMatches, _cfg: Configuration, cwd: PathBuf) -> Result<(), ExitError>
   where MI: repository::ModuleIterator<PathBuf, repository::Error> {

    let dirs = ProjectDirs::from("fyi", "sit", "sit-module").ok_or(ExitError::CantDeriveDirs)?;
    //
    // Module repository
    let module_repositories = env::var("SIT_MODULE_REPOSITORIES_DIR")
        .map(PathBuf::from)
        .unwrap_or(dirs.data_local_dir().join("repositories"));
    let module_repository_id: String = matches
        .value_of("module-repository")
        .map(String::from)
        .unwrap_or("default".into());
    let module_repository_intended_path = module_repositories.join(&module_repository_id);

    let update = match Repository::find_in_or_above(
        ".sit",
        &module_repository_intended_path,
    ) {
        Some(_) => matches.subcommand_matches("update").is_some(),
        None => true,
    };


    // sit module update
    if cfg!(feature = "module-manager-fetch") && update {
        let mut multibar = pbr::MultiBar::on(::std::io::stderr());

        let base_url: String = env::var(
            format!("SIT_MODULE_REPOSITORY_{}", module_repository_id).to_uppercase(),
        ).unwrap_or(DEFAULT_MODULE_REPOSITORY_URL.into());
        let url: String = if base_url.starts_with("git+") {
            (&base_url[4..]).into()
        } else {
            base_url
        };

        let mut objects_progress_bar = multibar.create_bar(100);
        objects_progress_bar.set(0);

        if module_repository_intended_path.is_dir() {
            thread::spawn(move || {
                let repo = git2::Repository::open(&module_repository_intended_path)?;
                let result = cross_host_enabled_git_operation(
                    |url| {
                        objects_progress_bar.message(&format!("[sit module] Fetching from {}: ", url));
                        objects_progress_bar.tick();
                        let mut remote_callbacks = git2::RemoteCallbacks::new();
                        remote_callbacks.transfer_progress(|progress| {
                            objects_progress_bar.message(&format!(
                                "[sit module] Objects ({}/{}) ",
                                progress.received_objects(),
                                progress.total_objects()
                            ));
                            objects_progress_bar.set(
                                (progress.received_objects() as f64
                                    / progress.total_objects() as f64
                                    * 100.0) as u64,
                            );
                            true
                        });
                        let mut git_fetch_options = git2::FetchOptions::new();
                        git_fetch_options.remote_callbacks(remote_callbacks);
                        repo.remote_anonymous(url)?.fetch(
                            &["master"],
                            Some(&mut git_fetch_options),
                            None,
                        )
                    },
                    &url,
                );
                repo.head().and_then(|r| {
                    objects_progress_bar.finish_println(&format!(
                        "[sit module] Module repository `{}` updated to {}",
                        &module_repository_id,
                        r.target().unwrap()
                    ));
                    Ok(())
                })?;
                result
            });
        } else {
            thread::spawn(move || {
                let result = cross_host_enabled_git_operation(
                    |url| {
                        objects_progress_bar.message(&format!("[sit module] Fetching from {}: ", url));
                        objects_progress_bar.tick();
                        let mut remote_callbacks = git2::RemoteCallbacks::new();
                        remote_callbacks.transfer_progress(|progress| {
                            objects_progress_bar.message(&format!(
                                "[sit module] Objects ({}/{}) ",
                                progress.received_objects(),
                                progress.total_objects()
                            ));
                            objects_progress_bar.set(
                                (progress.received_objects() as f64
                                    / progress.total_objects() as f64
                                    * 100.0) as u64,
                            );
                            true
                        });
                        let mut git_fetch_options = git2::FetchOptions::new();
                        git_fetch_options.remote_callbacks(remote_callbacks);
                        let mut builder = git2::build::RepoBuilder::new();
                        builder.fetch_options(git_fetch_options);
                        builder.clone(url, &module_repository_intended_path)
                    },
                    &url,
                );
                result
                    .and_then(|repo| {
                        repo.head().and_then(|r| {
                            objects_progress_bar.finish_println(&format!(
                                "[sit module] Module repository `{}` initialized at {}",
                                &module_repository_id,
                                r.target().unwrap()
                            ));
                            Ok(())
                        })
                    })
                    .unwrap_or(());
            });
        }

        multibar.listen();
        return Ok(());
    }

    let module_repository_path = match Repository::find_in_or_above(
        ".sit",
        module_repository_intended_path,
    ) {
        Some(path) => path,
        None => {
            let err = format!("Module repository `{}` not found, please try `sit module -m {} update` to provision it",
                              module_repository_id, module_repository_id);
            return Err(ExitError::Failure(err));
        }
    };

    // sit module path 
    if let Some(_) = matches.subcommand_matches("path") {
        println!("{}", module_repository_path.to_str().unwrap());
        return Ok(());
    }

    let sit_module_cmd = env::var("SIT_MODULE_MANAGER");

    if sit_module_cmd.is_ok() && sit_module_cmd.unwrap() == "list-modules" {
        let module_repo = Repository::open(module_repository_path).unwrap();
        use crate::module_iter::ScriptModule;
        match module_repo.config().clone().extra().get("external_module_manager") {
            Some(serde_json::Value::String(name)) => {
                let original_module_repo = module_repo.clone();
                list_modules(repo, module_repo.with_module_iterator(ScriptModule(original_module_repo, cwd.clone(), name.to_string())), cwd)
            }
            _ => {
                if module_repo.config().extra().contains_key("modules") {
                    let original_module_repo = module_repo.clone();
                    list_modules(repo, module_repo.with_module_iterator(ScriptModule(original_module_repo, cwd.clone(), "module".into())), cwd)
                } else {
                    list_modules(repo, module_repo, cwd)
                }
            }
        };

        fn list_modules<MI1, MI2>(repo: Repository<MI1>, module_repo: Repository<MI2>, cwd: PathBuf)
            where MI2: repository::ModuleIterator<PathBuf, repository::Error> {
                use sit_core::path::ResolvePath;
                use std::path::Path;
                let requirements = repo.config().extra().get("modules").unwrap().to_owned();
                let mut obj: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
                obj.insert("requirements".into(), requirements);
                let mut reducer = sit_core::reducers::duktape::DuktapeReducer::new(&module_repo).unwrap();
                let state = module_repo.initialize_state(obj);
                let result = module_repo.reduce_with_reducer_and_state(&mut reducer, state).expect("can't reduce");
                for (_mod, path_str) in result.get("modules").unwrap_or(&serde_json::Value::Object(serde_json::Map::new())).as_object().unwrap().iter() {
                    let path = Path::new(path_str.as_str().unwrap()).to_path_buf();
                    println!("{}", cwd.join(&path).resolve_dir("/").unwrap_or(path).to_str().unwrap());
                }
            }
    }


    Ok(())
}
