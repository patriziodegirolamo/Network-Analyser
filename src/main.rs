extern crate core;

use std::io;
use traffic_analyser::NetworkAnalyser;

fn main() {

    let mut na = NetworkAnalyser::new(); // Network Analyser with default values

    let mut res = na.init(); // Customize parameters

    if res.is_err(){
        println!("{}", err);
        return;
    }

    res= na.start();

    if res.is_err(){
        println!("{}", err);
        return;
    }

    let mut cmd = String::new();
    loop {
        cmd.clear();
        if io::stdin().read_line(&mut cmd).is_ok() {
            match cmd.trim() {
                "P" | "p" => na.pause().unwrap_or_else(|err| println!("{}", err) ),

                "X" | "x" => na.quit().unwrap_or_else(|err| println!("{}", err) ),
                "R" | "r" => na.resume().unwrap_or_else(|err| println!("{}", err) ),
                _ => println!("> [Error]: Unknown command")
            }
        } else {
            println!("> [Error]: Please Try again");
        }
    }
}