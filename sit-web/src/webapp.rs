#[allow(dead_code)]
mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));

    use rouille::{Response, ResponseBody};
    use mime_guess::get_mime_type_str;
    use std::path::PathBuf;
    use blake2::Blake2b;
    use digest::{Input, VariableOutput};
    use hex;

    impl<'a> Into<(Response, String)> for &'a File {
        fn into(self) -> (Response, String) {
            let mut hasher = Blake2b::new(20).unwrap();
            let mut result = vec![0; 20];
            hasher.process(self.contents);
            let hash = hex::encode(hasher.variable_result(&mut result).unwrap());
            (match get_mime_type_str(PathBuf::from(self.name()).extension().unwrap().to_str().unwrap()) {
                None => Response {
                    status_code: 200,
                    headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                    data: ResponseBody::from_data(self.contents),
                    upgrade: None,
                },
                Some(content_type) => Response {
                    status_code: 200,
                    headers: vec![("Content-Type".into(), content_type.into())],
                    data: ResponseBody::from_data(self.contents),
                    upgrade: None,
                },
            }, hash)
        }
    }

    use std::collections::HashMap;

    lazy_static! {
       pub static ref ASSETS: HashMap<PathBuf, File> = {
         let mut map = HashMap::new();
         let mut prefix = PathBuf::from(FILES.find("index.html").unwrap().path());
         prefix.pop();
         for entry in FILES.walk() {
            match entry {
               DirEntry::File(f) => {
                  let path = PathBuf::from(f.path().strip_prefix(&prefix).unwrap());
                  map.insert(path.clone(), f.clone());
                  let super_path = PathBuf::from("super").join(path);
                  map.insert(super_path, f.clone());
               },
               _ => (),
            }
         }
         map
       };
    }

}
use self::assets::ASSETS;

use rouille::{start_server, Request, Response, ResponseBody};
use rouille::input::multipart::get_multipart_input;

use std::path::PathBuf;
use std::fs;
use std::net::ToSocketAddrs;

use sit_core::Repository;

use mime_guess::get_mime_type_str;

use std::ffi::OsString;

use rayon::prelude::*;

use tempdir;

use blake2::Blake2b;
use digest::{Input, VariableOutput};
use hex;

use serde_json;

fn path_to_response<P: Into<PathBuf>>(path: P, request: &Request) -> Response {
    let path: PathBuf = path.into();

    let mut file = fs::File::open(&path).unwrap();
    let mut buf = Vec::with_capacity(file.metadata().unwrap().len() as usize);
    use std::io::Read;
    file.read_to_end(&mut buf).unwrap();


    let mut hasher = Blake2b::new(20).unwrap();
    let mut result = vec![0; 20];
    hasher.process(&buf);
    let hash = hex::encode(hasher.variable_result(&mut result).unwrap());

    match get_mime_type_str(path.extension().unwrap_or(&OsString::new()).to_str().unwrap()) {
        None => Response {
            status_code: 200,
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            data: ResponseBody::from_data(buf),
            upgrade: None,
        },
        Some(content_type) => Response {
            status_code: 200,
            headers: vec![("Content-Type".into(), content_type.into())],
            data: ResponseBody::from_data(buf),
            upgrade: None,
        },
    }.with_etag(request, hash)
}

use itertools::Itertools;
use sit_core;

#[derive(Serialize)]
struct Config {
    readonly: bool,
}

pub fn start<A: ToSocketAddrs>(addr: A, config: sit_core::cfg::Configuration, repo: Repository, readonly: bool, overlays: Vec<&str>) {
    let mut overlays: Vec<_> = overlays.iter().map(|o| PathBuf::from(o)).collect();
    let assets: PathBuf = repo.path().join("web").into();
    overlays.push(assets);
    for module_name in repo.module_iter().unwrap() {
        overlays.push(repo.modules_path().join(module_name).join("web").into());
    }
    let repo_config = Config {
      readonly,
    };
    start_server(addr, move |request|
        router!(request,
        (GET) (/user/config) => {
          Response::json(&config)
        },
        (GET) (/config) => {
           Response::json(&repo_config)
        },
        (GET) (/api/items/{filter_expr: String}/{query_expr: String}) => {
            use jmespath;
            use sit_core::item::ItemReduction;
            let items = repo.item_iter().expect("can't list items");
            let mut reducer = sit_core::reducers::duktape::DuktapeReducer::new(&repo).unwrap();
            let items_with_reducers: Vec<_> =  items.into_iter().map(|i| (i, reducer.clone())).collect();

            let filter_defined = filter_expr != "";
            let filter = if filter_defined {
                match jmespath::compile(&filter_expr) {
                  Ok(filter) => filter,
                  _ => return Response::empty_400(),
                }
            } else {
                jmespath::compile("`true`").unwrap()
            };
            let query = match jmespath::compile(&query_expr) {
                Ok(query) => query,
                _ => return Response::empty_400(),
            };

            let result: Vec<_> =
            items_with_reducers.into_par_iter()
                  .map(|(item, mut reducer)| {
                     item.reduce_with_reducer(&mut reducer).unwrap()
                  }).map(|json| {
                     let data = jmespath::Variable::from(serde_json::Value::Object(json));
                     let result = if filter_defined {
                        let res = filter.search(&data).unwrap();
                        res.is_boolean() && res.as_boolean().unwrap()
                     } else {
                        true
                     };
                     if result {
                        Some(query.search(&data).unwrap())
                     } else {
                        None
                     }
                  })
                 .filter(Option::is_some).collect();
            Response::json(&result)
        },
        (GET) (/api/item/{id: String}/{query_expr: String}) => {
            use jmespath;
            use sit_core::item::ItemReduction;
            use sit_core::Item;
            let mut reducer = sit_core::reducers::duktape::DuktapeReducer::new(&repo).unwrap();
            let query = match jmespath::compile(&query_expr) {
                Ok(query) => query,
                _ => return Response::empty_400(),
            };
            let item = match repo.item_iter().unwrap().find(|i| i.id() == id) {
                Some(item) => item,
                _ => return Response::empty_404(),
            };
            let reduced = item.reduce_with_reducer(&mut reducer).unwrap();
            let data = jmespath::Variable::from(serde_json::Value::Object(reduced));
            let result = query.search(&data).unwrap();
            Response::json(&result)
        },
        (GET) (/api/item/{id: String}/{record: String}/files) => {
            use sit_core::{Record, Item};
            let item = match repo.item_iter().unwrap().find(|i| i.id() == id) {
                Some(item) => item,
                None => return Response::empty_404(),
            };
            let record = match ::itertools::Itertools::flatten(item.record_iter().unwrap()).find(|r| r.encoded_hash() == record) {
               Some(record) => record,
               None => return Response::empty_404(),
            };
            let files: Vec<_> = record.file_iter().map(|(name, _)| name).collect();
            Response::json(&files)
        },
        (POST) (/api/item) => {
           if readonly { return Response::empty_404(); }
           use sit_core::Item;
           let item = repo.new_item().expect("can't create item");
           Response::json(&item.id())
        },
        (POST) (/api/item/{id: String}/records) => {
           if readonly { return Response::empty_404(); }
           use sit_core::{Item, Record};
           let mut item = match repo.item_iter().unwrap().find(|i| i.id() == id) {
                Some(item) => item,
                None => return Response::empty_404(),
           };

           let mut multipart = get_multipart_input(&request).expect("multipart request");
           let mut files = vec![];
           let mut link = true;
           let mut used_files = vec![];
           loop {
              let mut part = multipart.next();
              if part.is_none() {
                 break;
              }
              let mut field = part.unwrap();
              loop {
                 let path = {
                     let mut file = field.data.as_file().expect("files only");
                     let saved_file = file.save().temp().into_result().expect("can't save file");
                     saved_file.path
                 };
                 if field.name.starts_with(".prev/") {
                    link = false;
                 }
                 files.push((field.name.clone(), fs::File::open(&path).expect("can't open saved file")));
                 used_files.push(path);
                 match field.next_entry_inplace() {
                     Ok(Some(_)) => continue,
                     Ok(None) => break,
                     Err(e) => panic!(e),
                 }
              }
           }

           let tmp = tempdir::TempDir::new_in(repo.path(), "sit").unwrap();
           let record_path = tmp.path();

           let record = item.new_record_in(record_path, files.into_iter(), link).expect("can't create record");

           for file in used_files {
             fs::remove_file(file).expect("can't remove file");
           }

           if config.signing.enabled {
              use std::ffi::OsString;
              use std::io::Write;
              let program = match config.signing.gnupg {
                           Some(ref command) => command.clone(),
                           None => String::from("gpg"),
              };
              let key = match config.signing.key.clone() {
                  Some(key) => Some(OsString::from(key)),
                  None => None,
              };

              let mut command = ::std::process::Command::new(program);

              command
                   .stdin(::std::process::Stdio::piped())
                   .stdout(::std::process::Stdio::piped())
                   .arg("--sign")
                   .arg("--armor")
                   .arg("--detach-sign")
                   .arg("-o")
                   .arg("-");

              if key.is_some() {
                   let _ = command.arg("--default-key").arg(key.unwrap());
              }

              let mut child = command.spawn().expect("failed spawning gnupg");

              {
                  let mut stdin = child.stdin.as_mut().expect("Failed to open stdin");
                  stdin.write_all(record.encoded_hash().as_bytes()).expect("Failed to write to stdin");
              }

              let output = child.wait_with_output().expect("failed to read stdout");

              if !output.status.success() {
                  eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
              } else {
                  use sit_core::repository::DynamicallyHashable;
                  let dynamically_hashed_record = record.dynamically_hashed();
                  let mut file = fs::File::create(record.actual_path().join(".signature"))
                               .expect("can't open signature file");
                 file.write(&output.stdout).expect("can't write signature file");
                 drop(file);
                 let new_hash = dynamically_hashed_record.encoded_hash();
                 let mut new_path = record.path();
                 new_path.pop();
                 new_path.push(&new_hash);
                 fs::rename(record.actual_path(), new_path).expect("can't rename record");
                 return Response::json(&new_hash);
             }

          } else {
                 fs::rename(record.actual_path(), record.path()).expect("can't rename record");
          }

          Response::json(&record.encoded_hash())
        },
        _ => {
        // Serve repository content
        if request.url().starts_with("/repo/") {
            let file = repo.path().join(&request.url()[6..]);
            if file.strip_prefix(repo.path()).is_err() {
               return Response::empty_404();
            }
            if file.is_file() {
                return path_to_response(file, request)
            } else if file.is_dir() {
                if let Ok(dir) = ::std::fs::read_dir(file) {
                    let res = dir.filter(Result::is_ok)
                       .map(Result::unwrap)
                       .map(|e| if e.file_type().unwrap().is_dir() {
                           let s = String::from(e.file_name().to_str().unwrap());
                           (s + "/").into()
                       } else {
                           e.file_name()
                       })
                       .map(|s|
                           String::from(s.to_str().unwrap())
                       )
                       .join("\n");
                    return Response {
                        status_code: 200,
                        headers: vec![],
                        data: ResponseBody::from_string(res),
                        upgrade: None,
                    }
                }
            }
            return Response::empty_404()
        }
        // Serve built-in or overridden assets
        let overriden_path =
        overlays.iter().map(|o| o.join(&request.url()[1..]))
                .find(|p| p.is_file());
        if let Some(path) = overriden_path {
           return path_to_response(path, request)
        } else {
            if let Some(file) = ASSETS.get(&PathBuf::from(&request.url()[1..])) {
                let (response, hash) = file.into();
                return response.with_etag(request, hash)
            }
        }
        // Route the rest to /index.html for the web app to figure out
        let custom_index =
        overlays.iter().map(|o| o.join("index.html"))
                .find(|p| p.is_file());

        if let Some(index) = custom_index {
           path_to_response(index, request)
        } else {
           let (response, hash) = ASSETS.get(&PathBuf::from("index.html")).unwrap().into();
           response.with_etag(request, hash)
        }
      }
      ))

}

