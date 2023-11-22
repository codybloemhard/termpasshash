use argon2::{ Argon2, Algorithm, Version, Params };
use base64::{ Engine, engine::general_purpose };
use sha3::{ Sha3_512, Digest };

use cli_clipboard::{ ClipboardContext, ClipboardProvider };
use term_basics_linux as tbl;
use zen_colour::*;

fn main() {
    let args = lapp::parse_args("
        A program to hash your passwords.
        You can use the hash it self as a password for websites, etc.
        -l,--legacy //Use SHA3-512 iterated as hashing procedure.
        -u,--unmask //Show the resulting hash in readable colours, instead of the masked version.
        -c,--create //Create a new hash, you will be asked twice to verify if they match.
        -p,--print //Print password masked or unmasked instead of copy to clipboard.
    ");

    let arg_legacy = args.get_bool("legacy");
    let arg_unmask = args.get_bool("unmask");
    let arg_create = args.get_bool("create");
    let arg_print = args.get_bool("print");

    println!("{BOLD}{CYAN}TermPassHash{RESET}");

    if arg_legacy {
        println!("{BOLD}{RED}WARNING{DEFAULT}: running in legacy {BOLD}{MAGENTA}SHA3-512 \
            iterated{DEFAULT} mode!{RESET}");
    }

    let res = if arg_create {
        let h0 = hash(arg_legacy);
        println!("{BOLD}{MAGENTA}Verify:{RESET}");
        let h1 = hash(arg_legacy);
        if h0 != h1 {
            print!("{BOLD}{RED}TermPassHash: Results did not match!{RESET}");
            std::process::exit(-1);
        }
        h0
    } else {
        hash(arg_legacy)
    };

    if arg_print {
        if arg_unmask {
            println!("{res}");
        } else {
            println!("{GREEN}{BG_GREEN}{res}{RESET}");
        }
    } else {
        let mut ctx = ClipboardContext::new().unwrap();
        ctx.set_contents(res).unwrap();
        println!("{BOLD}Hash {GREEN}copied{DEFAULT} into clipboard!{RESET}");
        tbl::getch();
        let _ = ctx.clear();
        println!("{BOLD}Hash {RED}removed{DEFAULT} from clipboard!");
    }
}

fn hash(use_legacy: bool) -> String {
    if use_legacy {
        let password = prompt_min_length("Password: ", 0);
        let salt = prompt_min_length("Salt: ", 0);
        let rounds: usize = prompt_until_correct("Rounds: ");
        let mlen = prompt_until_correct("Max chars: ");
        let b16 = secure_hash_sha(password, salt, rounds);
        if let Some(mut res) = b16_to_b64(&b16) {
            res.truncate(mlen);
            res
        } else {
            panic!("{BOLD}{RED}TermPassHash: Could not convert B16 to B64!{RESET}")
        }
    } else {
        let password = prompt_min_length("Password: ", 8);
        let salt = prompt_min_length("Salt: ", 8);
        let mlen = prompt_until_correct("Max chars: ");
        let params = Params::new(1 << 21, 1, 1, Some(1024))
            .expect("{BOLD}{RED}Termpasshash: could not construct Argon2 parameters.{RESET}");
        let argon = Argon2::new(Algorithm::Argon2id, Version::default(), params);
        let mut outp = [0u8; 1024];
        argon.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut outp)
            .expect("{BOLD}{RED}Termpasshash: could not complete Argon2 hash.{RESET}");
        general_purpose::STANDARD.encode(&outp[..mlen])
    }
}

fn prompt_until_correct<T: std::str::FromStr>(msg: &str) -> T {
    loop {
        if let Some(xv) = tbl::string_to_value(&prompt_secure(msg)) {
            println!("{BOLD}{GREEN} > parsed{RESET}");
            break xv;
        }
        println!("{BOLD}{RED} > could not parse{RESET}");
    }
}

fn prompt_min_length(msg: &str, min: usize) -> String {
    loop {
        let string = prompt_secure(msg);
        let l = string.chars().count();
        if l >= min {
            println!("{BOLD}{GREEN} > valid{RESET}");
            break string;
        }
        println!("{BOLD}{RED} > too short: {DEFAULT}{l} {RED}< {DEFAULT}{min}{RESET}");
    }
}

fn prompt_secure(msg: &str) -> String {
    print!("{BOLD}{DEFAULT}{msg}{RESET}");
    tbl::discard_newline_on_prompt_nexttime();
    tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::None)
}

pub fn secure_hash_sha(password: String, mut salt: String, rounds: usize) -> String {
    salt.push_str(&password);
    let mut h = salt;
    for _ in 0..rounds {
        h = hash_sha(h);
    }
    h
}

pub fn hash_sha(string: String) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(string);
    let res = hasher.finalize();
    format!("{:x}", res)
}

pub fn b16_to_b64(string: &str) -> Option<String> {
    let x = hex::decode(string);
    match x {
        Result::Err(_) => Option::None,
        Result::Ok(xv) => Option::Some(general_purpose::STANDARD.encode(xv)),
    }
}

#[cfg(test)]
mod tests{
    use crate::*;

    #[test]
    fn test_hash0() {
        let x = secure_hash_sha("test".to_string(), "salt".to_string(), 1);
        assert_eq!(x, "2a247335dd9f59396a61822655998a9ddcd52912017d5f402a6140a8792b18426e90adf165d9e3dad5f954f850273e31739e1032fc970aef62cef036cb3e2143".to_string());
    }

    #[test]
    fn test_hash1() {
        let x = hash_sha("hello world".to_string());
        assert_eq!(x, "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a".to_string());
    }

    #[test]
    fn test_hash2() {
        let x = secure_hash_sha("test".to_string(), "salt".to_string(), 12);
        assert_eq!(x, "bee77f7ef2ce70d1a073b71da9c5ea74013dcfe70f3a5a46db160984958f49614e39788cfc0f84d086686f2c94f4c5fafb14f55959548eaa5dc06f0a42a6435c".to_string());
    }

    #[test]
    fn test_base64_0() {
        let x = b16_to_b64("2a247335dd9f59396a61822655998a9ddcd52912017d5f402a6140a8792b18426e90adf165d9e3dad5f954f850273e31739e1032fc970aef62cef036cb3e2143");
        assert_eq!(x, Option::Some("KiRzNd2fWTlqYYImVZmKndzVKRIBfV9AKmFAqHkrGEJukK3xZdnj2tX5VPhQJz4xc54QMvyXCu9izvA2yz4hQw==".to_string()));
    }

    #[test]
    fn test_base64_1() {
        let x = b16_to_b64("840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
        assert_eq!(x, Option::Some("hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==".to_string()));
    }
}

