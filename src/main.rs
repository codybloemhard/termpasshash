use sha3::{Sha3_512, Digest};
use term_basics_linux as tbl;
use lapp;
use std::cmp::{max};
use hex;
use base64;

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
    ");
    let arg_rounds = args.get_integer("rounds");
    let arg_length = args.get_integer("length");
    let arg_unmask = args.get_bool("unmask");
    let arg_password = args.get_string("password");
    let arg_salt = args.get_string("salt");
    let arg_mask = args.get_bool("mask");
    tbl::set_style(tbl::TextStyle::Bold);
    tbl::println_col("TermPassHash", tbl::UserColour::Magenta);
    tbl::set_colour(tbl::UserColour::Cyan, tbl::FGBG::FG);
    let password = if arg_password == ""{
        prompt_secure("Password: ", arg_mask, true)
    }else{
        arg_password
    };
    let salt = if arg_salt == ""{
        prompt_secure("Salt: ", arg_mask, true)
    }else{
        arg_salt
    };
    let rounds: usize = if arg_rounds == 0{
        prompt_until_correct("Rounds: ", arg_mask)
    }else{
        max(1, arg_rounds as usize)
    };
    let mlen: usize = if arg_length == 0{
        prompt_until_correct("Max chars: ", arg_mask)
    }else{
        arg_length as usize
    };
    let mut res = secure_hash(password, salt, rounds);
    res.truncate(mlen);
    print_hash(res, tbl::UserColour::Magenta, !arg_unmask);
}

fn print_hash<T: std::fmt::Display>(msg: T, col: tbl::UserColour, mask: bool){
    tbl::use_style(tbl::TextStyle::Std);
    if mask {
        tbl::println_cols(msg, col.clone(), col);
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
            tbl::println_col(" > parsed", tbl::UserColour::Green);
            return xv;
        }else{
            tbl::println_col(" > could not parse", tbl::UserColour::Red);
        }
    }
}

fn prompt_secure(msg: &str, mask: bool, endln: bool) -> String{
    tbl::print(msg);
    tbl::use_colour(tbl::UserColour::Yellow, tbl::FGBG::FG);
    let string;
    tbl::discard_newline_on_prompt_nexttime();
    if mask{
        string = tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::Substitude('*'));
        if endln { tbl::println(""); }
    }else{
        string = tbl::input_field_custom(&mut tbl::InputHistory::new(0), tbl::PromptChar::None);
        if endln { tbl::println_col(" > parsed", tbl::UserColour::Green); }
    };
    tbl::restore_colour(tbl::FGBG::FG);
    string
}

fn secure_hash(password: String, mut salt: String, rounds: usize) -> String{
    salt.push_str(&password);
    let mut h = salt;
    for _ in 0..rounds{
        h = hash(h);
    }
    h
}

fn hash(string: String) -> String{
    let mut hasher = Sha3_512::new();
    hasher.input(string);
    let res = hasher.result();
    format!("{:x}", res)
}

fn b16_to_b64(string: &str) -> Option<String>{
    let x = hex::decode(string);
    match x{
        Result::Err(_) => Option::None,
        Result::Ok(xv) => Option::Some(base64::encode(&xv)),
    }
}
