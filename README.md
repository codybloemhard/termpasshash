# termpasshash
A simple tool for hashing passwords in the terminal.
## what?
You can use hash passwords using a salt and a specified number of hashing rounds.
You can also truncate the output to a specified number of characters.
The idea is to use the hash itself as the password for websites etc.
The hashing algorithm used is SHA3-512.
The program will prompt you for the needed information.
## why?
* A hash can be long, complicated and hard to guess.
* It can be generated from a more human friendly password.
* A small change in the password and the hash will change a lot.
* As it runs locally and is opensource(you can compile your self) you can be the application does not send the data anywhere.
## --help
-r,--rounds (default 0) //How many rounds of hashing we will do. 0 means you will be prompted for it.
-l,--length (default 0) //How long the final output is, maximum. 0 means you will be prompted for it.
-u,--unmask //Show the resulting hash in readable colours, instead of the masked version.
-p,--password (default '') //The password to be hashed. If '' you will be prompted for it. Be carefull using this flag: never show the password as plaintext on screen.
-s,--salt (default '') //The salt to be used. If '' you will be promted for it. Be carefull using this flag if you want your salt to be secret.
-m,--mask //Mask the user input by substituting the characters with an '*'. Normally nothing is printed at all.
-b,--base16 //Use base16(hexadecimal) instead of base64
-c,--create //Create a new hash, you will be asked twice to verify if they match.
## compiling
Download the Rust language. Go to the root directory, the directory that contains the directory ```src``` and the file ```Cargo.toml```.
compile with ```cargo build --release```.
## about
This code is licenced under the MIT license. I am not responsible for what you do with it, use at own risk!
You should research the security of the program, algorithm used, process and idea of this application before you use it.
It is recommended that you read the source code and compile it yourself before using.
