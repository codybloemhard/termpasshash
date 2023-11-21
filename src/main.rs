use argon2::{ Argon2, Algorithm, Version, Params };
use base64::{ Engine, engine::general_purpose };
use sha3::{ Sha3_512, Digest };

use cli_clipboard::{ ClipboardContext, ClipboardProvider };
use term_basics_linux as tbl;

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

    tbl::set_style(tbl::TextStyle::Bold);
    tbl::println_col("TermPassHash", tbl::UC::Magenta);
    tbl::set_colour(tbl::UC::Cyan, tbl::XG::FG);

    if arg_legacy {
        println!("WARNING: running in legacy SHA3-512 iterated mode!");
    }

    let mut last = String::new();
    let mut ok = false;
    let mut mlen;
    let mut res = loop {
        let password = prompt_secure("Password: ", false, true);
        let salt = prompt_secure("Salt: ", false, true);
        let res = if arg_legacy {
            let rounds: usize = prompt_until_correct("Rounds: ", false);
            mlen = prompt_until_correct("Max chars: ", false);
            let b16 = secure_hash_sha(password, salt, rounds);
            if let Some(res) = b16_to_b64(&b16) {
                res
            } else {
                panic!("TermPassHash: Could not convert B16 to B64!")
            }
        } else {
            mlen = prompt_until_correct("Max chars: ", false);
            let params = Params::new(1 << 21, 1, 1, Some(1024))
                .expect("Termpasshash: could not construct Argon2 parameters.");
            let argon = Argon2::new(Algorithm::Argon2id, Version::default(), params);
            let mut outp = [0u8; 1024];
            argon.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut outp)
                .expect("Termpasshash: could not complete Argon2 hash.");
            general_purpose::STANDARD.encode(&outp[..mlen])
        };
        if !arg_create {
            ok = true;
            break res;
        } else if arg_create && last.is_empty() {
            last = res;
            tbl::println_col("Verify:", tbl::UC::Magenta);
        } else if arg_create && !last.is_empty() && last == res {
            ok = true;
            break res;
        } else if arg_create && !last.is_empty() && last != res {
            break String::new();
        }
    };

    if !ok {
        fatal_error("TermPassHash: Results did not match!");
    }
    res.truncate(mlen);
    if arg_print {
        print_hash(&res, tbl::UC::Magenta, !arg_unmask);
    } else {
        let mut ctx = ClipboardContext::new().unwrap();
        ctx.set_contents(res).unwrap();
        tbl::use_style(tbl::TextStyle::Bold);
        tbl::set_colours(tbl::UC::Cyan, tbl::UC::Std);
        tbl::println("Hash copied into clipboard!");
        tbl::getch();
        let _ = ctx.clear();
        tbl::println("Hash removed from clipboard!");
    }
}

fn fatal_error(msg: &str) {
    tbl::println_cols_style(msg, tbl::UC::Red, tbl::UC::Std, tbl::TextStyle::Bold);
    std::process::exit(-1);
}

fn print_hash<T: std::fmt::Display>(msg: &T, col: tbl::UC, mask: bool) {
    tbl::use_style(tbl::TextStyle::Std);
    if mask {
        tbl::println_cols(msg, col, col);
    } else {
        tbl::println_col(msg, col);
    }
    tbl::restore_style();
}

fn prompt_until_correct<T: std::str::FromStr>(msg: &str, mask: bool) -> T {
    loop {
        tbl::discard_newline_on_prompt_nexttime();
        let string = prompt_secure(msg, mask, false);
        let x: Option<T> = tbl::string_to_value(&string);
        if let Some(xv) = x {
            tbl::println_col(" > parsed", tbl::UC::Green);
            return xv;
        } else {
            tbl::println_col(" > could not parse", tbl::UC::Red);
        }
    }
}

fn prompt_secure(msg: &str, mask: bool, endln: bool) -> String {
    tbl::print(msg);
    tbl::use_colour(tbl::UC::Yellow, tbl::XG::FG);
    let string;
    tbl::discard_newline_on_prompt_nexttime();
    if mask {
        string = tbl::input_field_custom(
            &mut tbl::InputHistory::new(0),
            tbl::PromptChar::Substitude('*')
        );
        if endln { tbl::println(""); }
    } else {
        string = tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::None);
        if endln { tbl::println_col(" > parsed", tbl::UC::Green); }
    };
    tbl::restore_colour(tbl::XG::FG);
    string
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

