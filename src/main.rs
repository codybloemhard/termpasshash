use sha3::{Sha3_512, Digest};
use term_basics_linux as tbl;

fn main() {
    tbl::set_style(tbl::TextStyle::Bold);
    tbl::println_col("TermPassHash", tbl::UserColour::Magenta);
    tbl::set_colour(tbl::UserColour::Cyan, tbl::FGBG::FG);
    let password = prompt_secure("Password: ");
    let salt = prompt_secure("Salt: ");
    let rounds = prompt_until_correct("Rounds: ");
    let mlen: usize = prompt_until_correct("Max chars: ");
    let mut res = secure_hash(password, salt, rounds);
    res.truncate(mlen);
    print_masked(res, tbl::UserColour::Magenta);
}

fn print_masked<T: std::fmt::Display>(msg: T, col: tbl::UserColour){
    tbl::use_style(tbl::TextStyle::Std);
    tbl::println_cols(msg, col.clone(), col);
    tbl::restore_style();
}

fn prompt_until_correct<T: std::str::FromStr>(msg: &str) -> T{
    loop{
        let string = prompt_secure(msg);
        let x: Option<T> = tbl::string_to_value(&string);
        if let Some(xv) = x {
            return xv;
        }else{
            tbl::println_col(" > could not parse", tbl::UserColour::Red);
        }
    }
}

fn prompt_secure(msg: &str) -> String{
    tbl::print(msg);
    tbl::use_colour(tbl::UserColour::Yellow, tbl::FGBG::FG);
    let string = tbl::input_field_hidden('*');
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
