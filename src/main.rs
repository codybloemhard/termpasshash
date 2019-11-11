use sha3::{Sha3_512, Digest};
use term_basics_linux as tbl;

fn main() {
    println!("{}", secure_hash("hahayes".to_string(), "cody".to_string(), 10));
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
