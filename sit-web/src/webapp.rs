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

use sit_core::{Repository, reducers::duktape::DuktapeReducer, record::OrderedFiles};
use std::io::Cursor;

use mime_guess::get_mime_type_str;

use std::ffi::OsString;

use rayon::prelude::*;

use blake2::Blake2b;
use digest::{Input, VariableOutput};
use hex;

use serde_json;

use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use thread_local::ThreadLocal;

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

#[cfg(feature = "password-protection")]
fn scrypt_string(log_n: u8, r: u32, p: u32, salt: &[u8], dk: &[u8]) -> String {
    let mut result = "$rscrypt$".to_string();
    use data_encoding::BASE64;
    use byteorder::{ByteOrder, LittleEndian};
    if r < 256 && p < 256 {
        result.push_str("0$");
        let mut tmp = [0u8; 3];
        tmp[0] = log_n;
        tmp[1] = r as u8;
        tmp[2] = p as u8;
        result.push_str(&BASE64.encode(&tmp));
    } else {
        result.push_str("1$");
        let mut tmp = [0u8; 9];
        tmp[0] = log_n;
        LittleEndian::write_u32(&mut tmp[1..5], r);
        LittleEndian::write_u32(&mut tmp[5..9], p);
        result.push_str(&BASE64.encode(&tmp));
    }
    result.push('$');
    result.push_str(&BASE64.encode(&salt));
    result.push('$');
    result.push_str(&BASE64.encode(&dk));
    result.push('$');

    result
}
#[cfg(feature = "password-protection")]
fn scrypt_check(password: &str, hashed_value: &str) -> Result<(bool, Vec<u8>), &'static str> {
    fn read_u32v_le(dst: &mut[u32], input: &[u8]) {
        use std::{ptr, mem};
        assert_eq!(dst.len() * 4, input.len());
        unsafe {
            let mut x: *mut u32 = dst.get_unchecked_mut(0);
            let mut y: *const u8 = input.get_unchecked(0);
            for _ in 0..dst.len() {
                let mut tmp: u32 = mem::uninitialized();
                ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
                *x = u32::from_le(tmp);
                x = x.offset(1);
                y = y.offset(4);
            }
        }
    }

    use data_encoding::BASE64;
    use byteorder::{ByteOrder, LittleEndian};
    use ring_pwhash::scrypt::{scrypt, ScryptParams};
    static ERR_STR: &'static str = "Hash is not in Rust Scrypt format.";

    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    match iter.next() {
        Some(x) if x == "" => (),
        _ => return Err(ERR_STR),
    }

    // Check the name
    match iter.next() {
        Some(t) if t == "rscrypt" => (),
        _ => return Err(ERR_STR),
    }

    // Parse format - currenlty only version 0 (compact) and 1 (expanded) are supported
    let fstr = match iter.next() {
        Some(fstr) => fstr,
        None => return Err(ERR_STR),
    };

    // Parse the parameters - the size of them depends on the if we are using the compact or
    // expanded format
    let pvec = match iter.next() {
        Some(pstr) => match BASE64.decode(pstr.as_bytes()) {
            Ok(x) => x,
            Err(_) => return Err(ERR_STR)
        },
        None => return Err(ERR_STR)
    };

    let params = match fstr {
        "0" => {
            if pvec.len() != 3 { return Err(ERR_STR); }
            let log_n = pvec[0];
            let r = pvec[1] as u32;
            let p = pvec[2] as u32;
            ScryptParams::new(log_n, r, p)
        }
        "1" => {
            if pvec.len() != 9 { return Err(ERR_STR); }
            let log_n = pvec[0];
            let mut pval = [0u32; 2];
            read_u32v_le(&mut pval, &pvec[1..9]);
            ScryptParams::new(log_n, pval[0], pval[1])
        }
        _ => return Err(ERR_STR)
    };

    // Salt
    let salt = match iter.next() {
        Some(sstr) => match BASE64.decode(sstr.as_bytes()) {
            Ok(salt) => salt,
            Err(_) => return Err(ERR_STR)
        },
        None => return Err(ERR_STR)
    };

    // Hashed value
    let hash = match iter.next() {
        Some(hstr) => match BASE64.decode(hstr.as_bytes()) {
            Ok(hash) => hash,
            Err(_) => return Err(ERR_STR)
        },
        None => return Err(ERR_STR)
    };

    // Make sure that the input ends with a "$"
    match iter.next() {
        Some(x) if x == "" => (),
        _ => return Err(ERR_STR)
    }

    // Make sure there is no trailing data after the final "$"
    if iter.next().is_some() {
        return Err(ERR_STR);
    }

    let mut output = vec![0u8; hash.len() * 2];
    scrypt(password.as_bytes(), &*salt, &params, &mut output);

    Ok((::ring::constant_time::verify_slices_are_equal(&output[0..hash.len()], &hash).is_ok(), output))
}



pub fn start<A: ToSocketAddrs, MI: 'static + Send + Sync>(addr: A, config: sit_core::cfg::Configuration, repo: Repository<MI>, readonly: bool, overlays: Vec<&str>)
    where MI: sit_core::repository::ModuleIterator<PathBuf, sit_core::repository::Error> {
    let _prefix: String = "".into();
    #[cfg(feature = "password-protection")]
    let (_prefix, hashed, scrypt_params, public) = {
        println!("Generating new password");
//        use std::collections::HashMap;
        use qwerty::{Qwerty, Distribution};
        let password = Qwerty::new(Distribution::Alphanumeric, 16).generate();
//        let default_config = serde_json::Value::Object(HashMap::new());
//        let web_config = config.extra.get("sit-web").unwrap_or(&default_config);
        use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signature};
        use ring::rand::{SystemRandom, SecureRandom};
        use ring_pwhash::scrypt::{scrypt, scrypt_check, ScryptParams};
        use sha2;

        let log_n = 10u8;
        let r = 8u32;
        let p = 16u32;

        let params = ScryptParams::new(log_n, r, p);
        let rng = SystemRandom::new();
        // 128-bit random salt
        let mut salt = [0u8; 16];
        rng.fill(&mut salt).unwrap();
        // 512-bit derived key
        let mut dk = [0u8; 64];
        scrypt(password.as_bytes(), &salt, &params, &mut dk);

        let result = scrypt_string(log_n, r, p, &salt, &dk[0..32]);

        let secret = SecretKey::from_bytes(&dk[32..]).unwrap();
        let public = PublicKey::from_secret::<sha2::Sha512>(&secret);

        let prefix = format!("sit:{}@", password);
        (prefix, result, params, public)
    };

    println!("Serving on:");
    for a in addr.to_socket_addrs().unwrap() {
       println!("    http://{}{}", _prefix, a);
    }

    let mut overlays: Vec<_> = overlays.iter().map(|o| PathBuf::from(o)).collect();
    let assets: PathBuf = repo.path().join("web").into();
    overlays.push(assets);
    match repo.module_iter() {
        Ok(iter) => {
            for module_name in iter {
                let module_name = module_name.unwrap();
                overlays.push(repo.modules_path().join(module_name).join("web").into());
            }
        },
        Err(sit_core::RepositoryError::OtherError(str)) => {
            eprintln!("{}", str);
            return;
        },
        Err(e) => {
            eprintln!("error: {:?}", e);
            return;
        }
    }
    let repo_config = Config {
      readonly,
    };
    start_server(addr, move |request| {
        #[cfg(feature = "password-protection")]
        let signature = {
            use rouille::input;
            use ed25519_dalek::Signature;
            use data_encoding::BASE64URL;
            use sha2;
            let mut cookies = input::cookies(&request);
            loop {
                if let Some((_, val)) = cookies.find(|&(n, _)| n == "sit-auth") {
                    use sha2;
                    let signature = Signature::from_bytes(&BASE64URL.decode(val.as_bytes()).unwrap_or(vec![])).unwrap();
                    if public.verify::<sha2::Sha512>(b"This is a correct password",
                                                     &signature).is_ok() {
                        break signature
                    }
                }
                println!("has auth?");
                let auth = match input::basic_http_auth(request) {
                    Some(a) => a,
                    None => return Response::basic_http_auth_login_required("sit")
                };
                println!("auth {}", auth.password);
                let result = scrypt_check(&auth.password, &hashed).unwrap_or((false, vec![]));
                if !result.0 {
                    return Response::basic_http_auth_login_required("sit")
                }

                use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signature};
                let secret = SecretKey::from_bytes(&result.1[32..]).unwrap();
                let public = PublicKey::from_secret::<sha2::Sha512>(&secret);
                let keypair = Keypair { secret, public };

                break keypair.sign::<sha2::Sha512>(b"This is a correct password")
            }
        };

        let response = router!(request,
        (GET) (/user/config) => {
          Response::json(&config)
        },
        (GET) (/config) => {
           Response::json(&repo_config)
        },
        (GET) (/api/items/{filter_expr: String}/{query_expr: String}) => {
            use jmespath;
            use sit_core::item::ItemReduction;
            let items: Vec<_> = repo.item_iter().expect("can't list items").collect();
            let mut reducer = Arc::new(Mutex::new(sit_core::reducers::duktape::DuktapeReducer::new(&repo).unwrap()));
            let tl_reducer: ThreadLocal<RefCell<DuktapeReducer<sit_core::repository::Record<MI>, MI>>> = ThreadLocal::new();

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
            items.into_par_iter()
                  .map(|item| {
                     let mut reducer = tl_reducer.get_or(|| Box::new(RefCell::new(reducer.lock().unwrap().clone()))).borrow_mut();
                     reducer.reset_state();
                     item.reduce_with_reducer(&mut *reducer).unwrap()
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
                 used_files.push((field.name.clone(), path));
                 match field.next_entry_inplace() {
                     Ok(Some(_)) => continue,
                     Ok(None) => break,
                     Err(e) => panic!(e),
                 }
              }
           }

           let files: OrderedFiles<_> = used_files.iter().map(|(n, p)| (n.clone(), fs::File::open(p).expect("can't open saved file"))).into();
           let files_: OrderedFiles<_> = used_files.iter().map(|(n, p)| (n.clone(), fs::File::open(p).expect("can't open saved file"))).into();

           let files: OrderedFiles<_> = if config.signing.enabled {
              use std::ffi::OsString;
              use std::io::Write;
              let program = super::gnupg(&config).unwrap();
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
                  let mut hasher = repo.config().hashing_algorithm().hasher();
                  files_.hash(&mut *hasher).expect("failed hashing files");
                  let hash = hasher.result_box();
                  let encoded_hash = repo.config().encoding().encode(&hash);
                  stdin.write_all(encoded_hash.as_bytes()).expect("Failed to write to stdin");
              }

              let output = child.wait_with_output().expect("failed to read stdout");

              if !output.status.success() {
                  eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
                  return Response::text(String::from_utf8_lossy(&output.stderr)).with_status_code(500);
              } else {
                 let sig: OrderedFiles<_> = vec![(String::from(".signature"), Cursor::new(output.stdout))].into();
                 files + sig
             }

          } else {
              files.boxed()
          };

          let record = item.new_record(files, link).expect("can't create record");

          for (_, file) in used_files {
            fs::remove_file(file).expect("can't remove file");
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
      );

        #[cfg(not(feature = "password-protection"))] {
            response
        }
        #[cfg(feature = "password-protection")] {
            use data_encoding::BASE64URL;
            response.with_additional_header("Set-Cookie",format!("sit-auth={}; path=/", BASE64URL.encode(&signature.to_bytes())))
        }
    })

}

