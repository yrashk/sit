use clap::ArgMatches;
use std::fs;
use std::io::Read;
use rlua::prelude::*;

enum Language {
    Lua,
    Unknown,
}

use std::path::Path;

impl<'a> From<&'a ArgMatches<'a>> for Language {
    fn from(matches: &'a ArgMatches) -> Language {
        let language = matches.value_of("language");
        match language {
            None => match Path::new(matches.value_of("FILE").unwrap()).extension() {
                Some(s) if s == "lua" => Language::Lua,
                _ => Language::Unknown,
            },
            Some(s) if s == "lua" => Language::Lua,
            _ => Language::Unknown,
        }
    }
}

pub fn command(matches: &ArgMatches) -> i32 {
    let language = matches.into();
    match language {
        Language::Lua => {
            let lua = Lua::new();
            let mut f = fs::File::open(matches.value_of("FILE").unwrap()).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            let _: LuaValue = lua.exec(&s, Some(matches.value_of("FILE").unwrap().into())).unwrap();
            0
        },
        _ => {
            eprintln!("Unknown language");
            1
        },
    }
}
