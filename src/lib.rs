mod packet_handle;
mod tmp;
mod sniffer;
mod reporter;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex};
use packet_handle::{Filter};
use pnet_datalink::{NetworkInterface};
use std::thread::{JoinHandle};
use enum_iterator::all;
use regex::Regex;
use crate::packet_handle::{FilteredProtocol, Protocol};

#[derive(Debug)]
pub enum ErrorNetworkAnalyser{
    ErrorQuit,
    ErrorResume,
    ErrorPause
}

/*
impl ErrorQuit{
    pub fn new(msg: &str) -> Self{
        ErrorQuit{message: msg.to_string()}
    }
}

 */

impl Display for ErrorNetworkAnalyser{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error Network Analyser: {}", self)
    }
}

impl Error for ErrorNetworkAnalyser{}

enum StatusValue{
    Running,
    Paused,
    Exit,
}

pub struct Status{
    mutex: Mutex<StatusValue>,
    cvar: Condvar,
}

impl Status {
    pub fn new() -> Status{
        Status{
            mutex: Mutex::new(StatusValue::Running),
            cvar: Condvar::new()
        }
    }
}


pub struct NetworkAnalyser{
    interface: NetworkInterface,
    time_interval: usize,
    filename: String,
    filter: Filter,
    sniffer_handle: Option<JoinHandle<()>>,
    reporter_handle: Option<JoinHandle<()>>,
    status: Arc<Status>
}

impl Display for NetworkAnalyser {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interface: {}; time: {}, filename: {}, filter: {}", self.interface, self.time_interval, self.filename, self.filter)
    }
}

impl NetworkAnalyser {
    pub fn new() -> Self{
        let dft_interface = select_device_by_name(find_my_device_name(0));
        let dft_time_interval = 5;
        let dft_filename = "report.txt".to_string();
        let dft_filter = Filter::new();

        return Self{
            interface: dft_interface,
            time_interval: dft_time_interval,
            filename: dft_filename,
            filter: dft_filter,
            sniffer_handle: None,
            reporter_handle: None,
            status: Arc::new(Status::new())
        }
    }

    pub fn init(&mut self) -> Result<(), ErrorNetworkAnalyser>{
        //TODO: gestire errore di init_sniffing
        let (interface, time_interval, filename, filter) = init_sniffing();

        self.interface = interface;
        self.time_interval = time_interval;
        self.filename = filename;
        self.filter = filter;

        return Ok(());

    }

    pub fn start(&mut self) -> Result<(), ErrorNetworkAnalyser>{
        return Ok(())
    }

    pub fn pause(&mut self) -> Result<(), ErrorNetworkAnalyser>{
        return Ok(())
    }

    pub fn quit(&mut self){
        return
    }

    pub fn resume(&mut self) -> Result<(), ErrorNetworkAnalyser>{
        return Ok(())
    }
}


/**
Print the name and the description of all the network interfaces found
and returns the total number of interfaces found
 */
pub fn print_devices() -> usize {
    let interfaces = pnet_datalink::interfaces();
    let tot = interfaces.len();

    for (i, inter) in interfaces.into_iter().enumerate() {
        println!("{}:   {:?} {:?}", i, inter.name, inter.description);
    }

    return tot;
}

/**
Select a specific network interface given the name
it panics if the name is invalid or if there is no network interface with this name
 */
pub fn select_device_by_name(name: String) -> NetworkInterface {
    let interfaces = pnet_datalink::interfaces();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name));

    return chosen_interface;
}

pub fn find_my_device_name(index: usize) -> String {
    return pnet_datalink::interfaces().get(index).unwrap().clone().name;
}


pub enum State{
    Index,
    Time,
    File,
    Filter,
    IpSorg,
    IpDest,
    PortaSorg,
    PortaDest,
    Protocol,
}


fn init_sniffing() -> (NetworkInterface, usize, String, Filter) {
    let mut state = State::Index;
    let mut my_index = 0;
    let mut interface = select_device_by_name(find_my_device_name(my_index));
    let mut time_interval = 1;
    let mut filename = String::new();
    let mut filter = Filter::new();

    //TODO: handle the closing!!!!! -> error
    println!();
    println!("*************************************************************");
    println!("*************************************************************");
    println!("*************  N E T W O R K    S N I F F E R  **************");
    println!("*************************************************************");
    println!("*************************************************************");
    println!();
    println!();
    println!("*************************************************************");
    println!("                      INITIALIZATION                         ");
    println!("*************************************************************");
    /* Define the interface to use */


    loop{
        match state {
            State::Index => {
                println!("> Which of the following interfaces you want to sniff?");
                let tot_interfaces = print_devices();
                print!("> Select an index: ");
                io::stdout().flush().expect("Error");

                let mut my_index_str = String::new();

                //read a line
                match io::stdin().read_line(&mut my_index_str){
                    Ok(_) => {
                        let cmd = my_index_str.trim();
                        match cmd.parse::<usize>() {
                            Ok(my_index) => {
                                if my_index < tot_interfaces {
                                    let dev_name = find_my_device_name(my_index);
                                    println!();
                                    println!("> Ok, you selected:  {:?}", dev_name);
                                    interface = select_device_by_name(dev_name);
                                    println!("> Setting the interface in promiscous mode... "); // The promiscous mode is the default configuration (line 167 file lib.rs in pnet-datalink module)
                                    state = State::Time;
                                }
                                else {
                                    println!("> Error: please select a valid number. Try Again.");
                                }
                            }
                            Err(err) => {
                                println!("> Error: {}", err);
                            }
                        }
                    }
                    Err(err) => {
                        println!("> Error: {}", err);
                    }
                }
            }
            State::Time => {
                println!("> Please, insert a time interval. [Press E to exit and start a new analysis] [by default is set to 1]");
                println!();
                print!("> Time interval (s): ");
                io::stdout().flush().expect("Error");

                let mut time_interval_str = String::new();

                match io::stdin().read_line(&mut time_interval_str) {
                    Ok(_) => {
                        let cmd = time_interval_str.trim();
                        if cmd == ""{
                            state = State::File;
                        }
                        else{
                            match cmd.parse::<usize>() {
                                Ok(tmp) => {
                                    state = State::File;
                                    time_interval = tmp;
                                }
                                Err(err) => println!("> Error: {}", err)
                            }
                        }
                    }
                    Err(err) => println!("> Error: {}", err)

                }
            }
            State::File => {
                println!();
                println!("> Please, insert the name of the file where we will save the report in \".txt\" format. By default is \"report.txt\"");
                filename = String::new();
                io::stdout().flush().expect("Error");
                match io::stdin().read_line(&mut filename) {
                    Ok(_) => {
                        let cmd = filename.trim();
                        if cmd == ""{
                            state = State::Filter;
                            filename = "report.txt".to_string();
                        }
                        else{
                            let reg = Regex::new(r"^[\w,\s-]+\.txt$").unwrap();
                            if reg.is_match(&*cmd) {
                                filename = cmd.to_string();
                                state = State::Filter;
                            }
                            else{
                                println!("Please, write a correct filename in txt format! It must not contain :       \\ /:*?\"<>|");
                            }
                        }
                    }
                    Err(err) => {
                        println!("Error: {}", err);
                    }
                }
            }
            State::Filter => {
                println!("> do you want to add a filter? [Y, N]");
                io::stdout().flush().expect("Error");

                let mut filt = String::new();
                match io::stdin().read_line(&mut filt){
                    Ok(_) => {
                        let cmd = filt.trim();
                        match cmd {
                            "Y" | "y" => state = State::IpSorg,
                            "" | "N" | "n" => state = break,
                            _ => println!("> Please, write a correct answer"),
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            State::IpSorg => {
                println!("> Please insert the source ip address or [X, or nothing] otherwise");
                let mut ip_str = String::new();

                match io::stdin().read_line(&mut ip_str) {
                    Ok(_) => {
                        ip_str = ip_str.trim().to_string();

                        if ip_str == "" || ip_str == "X" || ip_str == "x"{
                            state = State::IpDest;
                            continue;
                        }

                        match validate_ip_address(ip_str) {
                            Ok(addr) => {
                                filter.set_ip_srg(addr);
                                state = State::IpDest;
                            }
                            Err(err) => println!("Error: {}", err)
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            State::IpDest => {
                println!("> Please insert the destination ip address or [X, or nothing] otherwise");
                let mut ip_str = String::new();

                match io::stdin().read_line(&mut ip_str) {
                    Ok(_) => {
                        ip_str = ip_str.trim().to_string();

                        if ip_str == "" || ip_str == "X" || ip_str == "x"{
                            state = State::PortaSorg;
                            continue;
                        }

                        match validate_ip_address(ip_str) {
                            Ok(addr) => {
                                filter.set_ip_dest(addr);
                                state = State::PortaSorg;
                            }
                            Err(err) => println!("Error: {}", err)
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            State::PortaSorg => {
                println!("> Please insert the source port number or X otherwise");
                let mut prt_str = String::new();
                match io::stdin().read_line(&mut prt_str) {
                    Ok(_) => {
                        prt_str = prt_str.trim().to_string();

                        if prt_str == ""|| prt_str == "X" || prt_str == "x"{
                            state = State::PortaDest;
                            continue;
                        }

                        match prt_str.trim().parse::<u16>(){
                            Ok(val) => {
                                filter.set_prt_srg(val);
                                state = State::PortaDest;
                            }
                            Err(err) => {
                                println!("Error : {}", err);
                            }
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            State::PortaDest => {
                println!("> Please insert the destination port number or X otherwise");
                let mut prt_str = String::new();
                match io::stdin().read_line(&mut prt_str) {
                    Ok(_) => {
                        prt_str = prt_str.trim().to_string();

                        if prt_str == "" || prt_str == "X" || prt_str == "x"{
                            state = State::Protocol;
                            continue;
                        }
                        match prt_str.trim().parse::<u16>(){
                            Ok(val) => {
                                filter.set_prt_dest(val);
                                state = State::Protocol;
                            }
                            Err(err) => {
                                println!("Error : {}", err);
                            }
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            State::Protocol => {
                println!("> Please, choose one of the following protocols or [X or nothing] otherwise");
                let protocols :Vec<FilteredProtocol>= all::<FilteredProtocol>().collect::<Vec<_>>();
                for (ind, tmp) in protocols.iter().enumerate(){
                    println!("{}: {}", ind, tmp);
                }
                let mut cmd = String::new();

                match io::stdin().read_line(&mut cmd) {
                    Ok(_) => {
                        cmd = cmd.trim().to_string();

                        if cmd == "" || cmd == "X" || cmd == "x" {
                            break;
                        }

                        match cmd.parse::<usize>(){
                            Ok(val) => {
                                if val < protocols.len(){
                                    let protocol = protocols[val].to_string().parse::<Protocol>();
                                    match protocol{
                                        Ok(p) => {
                                            filter.set_protocol(p);
                                            break;
                                        }
                                        Err(err) => {
                                            println!("Error: {:?}", err)
                                        }
                                    }
                                }
                                else{
                                    println!("Error, wrong number");
                                }
                            }
                            Err(err) => println!("Error: {}", err)
                        }
                    }
                    Err(err) => println!("Error: {}", err)
                }

            }
        }
    }

    return (interface, time_interval, filename, filter);
}


pub fn validate_ip_address(ip_str: String) -> Result<IpAddr, String>{
    let vec_ip4 : Vec<&str> = ip_str.split(".").map(|x| x).collect();
    let vec_ip6 : Vec<&str> = ip_str.split(":").map(|x| x).collect();
    let mut error = String::new();
    if vec_ip4.len() == 4 {
        let mut correct = true;
        let mut tmp : Vec<u8> = vec![0; 4];
        for i in 0..4{
            match vec_ip4[i].parse::<u8>() {
                Ok(val) => {
                    tmp[i] = val;
                }
                Err(e) => {
                    correct = false;
                    error = e.to_string();
                }
            }
        }
        if correct {
            return Ok(IpAddr::V4(Ipv4Addr::new(tmp[0], tmp[1], tmp[2], tmp[3])));
        }
    }
    else if vec_ip6.len() == 8 {
        let mut correct = true;
        let mut tmp : Vec<u16> = vec![0; 8];
        for i in 0..8{
            match vec_ip6[i].parse::<u16>(){
                Ok(val) => {
                    tmp[i] = val;
                }
                Err(e) => {
                    correct = false;
                    error = e.to_string();
                }
            }
        }
        if correct {
            return Ok(IpAddr::V6(Ipv6Addr::new(tmp[0], tmp[1], tmp[2], tmp[3],
                                               tmp[4], tmp[5], tmp[6], tmp[7])));
        }
    }
    return Err("It is not an IPV4 or IPV6 address".to_string());
}