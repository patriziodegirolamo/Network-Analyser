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
                    na.pause().unwrap();
                    println!("main: sniffing paused...")
                },
                "X" | "x" => {
                    na.quit().unwrap();
                    println!("main: sniffing quitted...");
                    break;
                },
                "R" | "r" => {
                    if na.resume().is_ok() {
                        na.resume().unwrap();
                        println!("main: sniffing resumed...");
                        println!("SNIFFING...");
                    } else {
                        println!("sniffing is already running")
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