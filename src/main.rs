extern crate core;
use std::io;
use std::io::Write;
use traffic_analyser::{NetworkAnalyser};

fn main() {

    let mut na = NetworkAnalyser::new(); // Network Analyser with default values

    match na.init() // Customize parameters
    {
        Ok(_) => {}
        Err(e) => {
            println!("{}", e);
            return;}
    }

    match na.start() // Start the process
    {
        Ok(n) => {na = n;}
        Err(e) => {
            println!("{}", e);
            return;}
    }

    // Handle user commands
    let mut cmd = String::new();
    loop {
        print!(">> Command: [P to pause] [R to resume] [X to exit]  ");
        io::stdout().flush().expect("Error");
        cmd.clear();

        if io::stdin().read_line(&mut cmd).is_ok() {
            match cmd.trim() {
                "P" | "p" => na.pause().unwrap_or_else(|err| println!("{}", err) ),
                "X" | "x" => {
                    na.quit().unwrap_or_else(|err| println!("{}", err) );
                    break;
                },
                "R" | "r" => na.resume().unwrap_or_else(|err| println!("{}", err) ),
                _ => println!("> [Error]: Unknown command")
            }
        } else {
            println!("> [Error]: Please Try again");
        }
    }
}