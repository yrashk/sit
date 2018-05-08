use clap::ArgMatches;
use sit_core::{Repository, Item, Collection, repository::Error};
use std::io::ErrorKind as IoErrorKind;

fn item<'a, C: Collection<Error = Error>>(collection: C, named: Option<&str>) -> i32 {
    let item = if named.is_none() {
        collection.new_item()
    } else {
        collection.new_named_item(named.clone().unwrap())
    };
    match item {
        Ok(item) => {
            println!("{}", item.id());
            return 0;
        },
        Err(Error::IoError(err)) => {
            if err.kind() == IoErrorKind::AlreadyExists {
                eprintln!("Item {} already exists", named.unwrap());
                return 1;
            } else {
                panic!("can't create an item: {:?}", err)
            }
        },
        Err(err) =>
            panic!("can't create an item: {:?}", err),
    }
}

pub fn command(matches: &ArgMatches, repo: &Repository) -> i32 {
    let named = matches.value_of("id");
    match matches.value_of("collection") {
        None => item(repo, named),
        Some(name) => {
            let coll = repo.collection(name).expect("can't access collection");
            item(&coll, named)
        },
    }
}


