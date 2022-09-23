extern crate core;

use std::io;
use traffic_analyser::NetworkAnalyser;

fn main() {
    //new -> inserisce valori di default
    let mut na = NetworkAnalyser::new();

    //init -> inserisce i parametri dell'utente
    match na.init() {
        Ok(_) => {
            println!("{}", na)
        },
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    };

    na.start().unwrap();
    println!("SNIFFING...");
    loop{
        let mut cmd = String::new();
        if io::stdin().read_line(&mut cmd).is_ok() {
            match cmd.trim() {
                "P" | "p" => {
                    match na.pause() {
                        Ok(_) => println!("main: sniffing paused..."),
                        Err(err) => println!("{}",err)
                    }
                },
                "X" | "x" => {
                    match na.quit() {
                        Ok(_) => println!("main: sniffing quitted..."),
                        Err(err) => println!("{}", err)
                    }
                },
                "R" | "r" => {
                    match na.resume() {
                        Ok(_) => {
                            println!("main: sniffing resumed...");
                            println!("SNIFFING...");
                        }
                        Err(err) => println!("{}",err)//println!("sniffing is already running")
                    }
                },
                _ => println!("unknown command")
            }
        }
        else{
            println!("Error, try again");
        }
    }
}