use sha3::{ Sha3_512, Digest };
use term_basics_linux as tbl;
use std::cmp::max;
use cli_clipboard::{ ClipboardContext, ClipboardProvider };
use base64::{ Engine, engine::general_purpose };

fn main() {
    let args = lapp::parse_args("
        A program to hash your passwords.
        You can use the hash it self as a password for websites, etc.
        -r,--rounds (default 0) //How many rounds of hashing we will do. 0 means you will be prompted for it.
        -l,--length (default 0) //How long the final output is, maximum. 0 means you will be prompted for it.
        -u,--unmask //Show the resulting hash in readable colours, instead of the masked version.
        -p,--password (default '') //The password to be hashed. If '' you will be prompted for it. Be carefull using this flag: never show the password as plaintext on screen.
        -s,--salt (default '') //The salt to be used. If '' you will be promted for it. Be carefull using this flag if you want your salt to be secret.
        -m,--mask //Mask the user input by substituting the characters with an '*'. Normally nothing is printed at all.
        -b,--base16 //Use base16(hexadecimal) instead of base64
        -c,--create //Create a new hash, you will be asked twice to verify if they match.
        -P,--print //Print password masked or unmasked instead of copy to clipboard.
    ");
    let arg_rounds = args.get_integer("rounds");
    let arg_length = args.get_integer("length");
    let arg_unmask = args.get_bool("unmask");
    let arg_password = args.get_string("password");
    let arg_salt = args.get_string("salt");
    let arg_mask = args.get_bool("mask");
    let arg_base16 = args.get_bool("base16");
    let arg_create = args.get_bool("create");
    let arg_print = args.get_bool("print");

    tbl::set_style(tbl::TextStyle::Bold);
    tbl::println_col("TermPassHash", tbl::UC::Magenta);
    tbl::set_colour(tbl::UC::Cyan, tbl::XG::FG);

    let mut last = String::new();
    let mut ok = false;
    let mut mlen;
    let mut res = loop{
        let password = if arg_password.is_empty(){
            prompt_secure("Password: ", arg_mask, true)
        }else{
            arg_password.clone()
        };
        let salt = if arg_salt.is_empty(){
            prompt_secure("Salt: ", arg_mask, true)
        }else{
            arg_salt.clone()
        };
        let rounds: usize = if arg_rounds == 0{
            prompt_until_correct("Rounds: ", arg_mask)
        }else{
            max(1, arg_rounds as usize)
        };
        mlen = if arg_length == 0{
            prompt_until_correct("Max chars: ", arg_mask)
        }else{
            arg_length as usize
        };
        let mut res = secure_hash_sha(password, salt, rounds);
        if !arg_base16 {
            if let Some(x) = b16_to_b64(&res){
                res = x;
            }else{
                fatal_error("TermPassHash: Could not convert B16 to B64!")
            }
        }
        if !arg_create{
            ok = true;
            break res;
        }else if arg_create && last.is_empty(){
            last = res;
            tbl::println_col("Verify:", tbl::UC::Magenta);
        }else if arg_create && !last.is_empty() && last == res{
            ok = true;
            break res;
        }else if arg_create && !last.is_empty() && last != res{
            break String::new();
        }
    };

    if !ok{
        fatal_error("TermPassHash: Results did not match!");
    }
    res.truncate(mlen);
    if arg_print{
        print_hash(&res, tbl::UC::Magenta, !arg_unmask);
    }else{
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

fn fatal_error(msg: &str){
    tbl::println_cols_style(msg, tbl::UC::Red, tbl::UC::Std, tbl::TextStyle::Bold);
    std::process::exit(-1);
}

fn print_hash<T: std::fmt::Display>(msg: &T, col: tbl::UC, mask: bool){
    tbl::use_style(tbl::TextStyle::Std);
    if mask {
        tbl::println_cols(msg, col, col);
    }else{
        tbl::println_col(msg, col);
    }
    tbl::restore_style();
}

fn prompt_until_correct<T: std::str::FromStr>(msg: &str, mask: bool) -> T{
    loop{
        tbl::discard_newline_on_prompt_nexttime();
        let string = prompt_secure(msg, mask, false);
        let x: Option<T> = tbl::string_to_value(&string);
        if let Some(xv) = x {
            tbl::println_col(" > parsed", tbl::UC::Green);
            return xv;
        }else{
            tbl::println_col(" > could not parse", tbl::UC::Red);
        }
    }
}

fn prompt_secure(msg: &str, mask: bool, endln: bool) -> String{
    tbl::print(msg);
    tbl::use_colour(tbl::UC::Yellow, tbl::XG::FG);
    let string;
    tbl::discard_newline_on_prompt_nexttime();
    if mask{
        string = tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::Substitude('*'));
        if endln { tbl::println(""); }
    }else{
        string = tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::None);
        if endln { tbl::println_col(" > parsed", tbl::UC::Green); }
    };
    tbl::restore_colour(tbl::XG::FG);
    string
}

pub fn secure_hash_sha(password: String, mut salt: String, rounds: usize) -> String{
    salt.push_str(&password);
    let mut h = salt;
    for _ in 0..rounds{
        h = hash_sha(h);
    }
    h
}

pub fn hash_sha(string: String) -> String{
    let mut hasher = Sha3_512::new();
    hasher.update(string);
    let res = hasher.finalize();
    format!("{:x}", res)
}

pub fn b16_to_b64(string: &str) -> Option<String>{
    let x = hex::decode(string);
    match x{
        Result::Err(_) => Option::None,
        Result::Ok(xv) => Option::Some(general_purpose::STANDARD.encode(xv)),
    }
}

#[cfg(test)]
mod tests{

    use crate::*;

    #[test]
    fn test_hash0(){
        let x = secure_hash_sha("test".to_string(), "salt".to_string(), 1);
        assert_eq!(x, "2a247335dd9f59396a61822655998a9ddcd52912017d5f402a6140a8792b18426e90adf165d9e3dad5f954f850273e31739e1032fc970aef62cef036cb3e2143".to_string());
    }

    #[test]
    fn test_hash1(){
        let x = hash_sha("hello world".to_string());
        assert_eq!(x, "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a".to_string());
    }

    #[test]
    fn test_hash2(){
        let x = secure_hash_sha("test".to_string(), "salt".to_string(), 12);
        assert_eq!(x, "bee77f7ef2ce70d1a073b71da9c5ea74013dcfe70f3a5a46db160984958f49614e39788cfc0f84d086686f2c94f4c5fafb14f55959548eaa5dc06f0a42a6435c".to_string());
    }

    #[test]
    fn test_base64_0(){
        let x = b16_to_b64("2a247335dd9f59396a61822655998a9ddcd52912017d5f402a6140a8792b18426e90adf165d9e3dad5f954f850273e31739e1032fc970aef62cef036cb3e2143");
        assert_eq!(x, Option::Some("KiRzNd2fWTlqYYImVZmKndzVKRIBfV9AKmFAqHkrGEJukK3xZdnj2tX5VPhQJz4xc54QMvyXCu9izvA2yz4hQw==".to_string()));
    }

    #[test]
    fn test_base64_1(){
        let x = b16_to_b64("840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
        assert_eq!(x, Option::Some("hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==".to_string()));
    }
}

