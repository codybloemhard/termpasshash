use sha3::{Sha3_512, Digest};
use term_basics_linux as tbl;

fn main() {
    //tbl::println_cols_style("TermPassHash", tbl::UserColour::Cyan, tbl::UserColour::Std, tbl::TextStyle::Bold);
    tbl::set_style(tbl::TextStyle::Bold);
    tbl::println_col("TermPassHash", tbl::UserColour::Magenta);
    tbl::use_colour(tbl::UserColour::Cyan, tbl::FGBG::FG);
    let password = prompt_secure("Password: ");
    let salt = prompt_secure("Salt: ");
    let rounds;
    loop{
        let str_rounds = prompt_secure("Rounds: ");
        let x = tbl::string_to_value(&str_rounds);
        if let Some(xv) = x {
            rounds = xv;
            break;
        }
    }
    let res = secure_hash(password, salt, rounds);
    tbl::println_cols(res, tbl::UserColour::Magenta, tbl::UserColour::Magenta);
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
