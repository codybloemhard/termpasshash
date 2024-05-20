# termpasshash

A simple tool for hashing passwords in the terminal.

## what?

You can use hash passwords using a salt and a specified number of hashing rounds.
You can also truncate the output to a specified number of characters.
The idea is to use the hash itself as the password for websites etc.
The hashing algorithm used is Argon2.
The program will prompt you for the needed information.

## why?

* A hash can be long, complicated and hard to guess.
* It can be generated from a more human friendly password.
* A small change in the password and the hash will change a lot.
* As it runs locally and is opensource(you can compile your self) you can be sure the application does not send the data anywhere.

## --help

```
-l,--legacy //Use SHA3-512 iterated as hashing procedure.
-u,--unmask //Show the resulting hash in readable colours, instead of the masked version.
-c,--create //Create a new hash, you will be asked twice to verify if they match.
-p,--print //Print password masked or unmasked instead of copy to clipboard.
```

## compiling

Download the Rust language. Go to the root directory, the directory that contains the directory ```src``` and the file ```Cargo.toml```.
compile with ```cargo build --release```.

## about

This code is licenced under the MIT license. I am not responsible for what you do with it, use at own risk!
You should research the security of the program, algorithm used, process and idea of this application before you use it.
It is recommended that you read the source code and compile it yourself before using.
