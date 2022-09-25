mod packet_handle;
mod tmp;
mod sniffer;
mod reporter;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use packet_handle::{Filter};
use pnet_datalink::{Channel, NetworkInterface};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use enum_iterator::all;
use regex::Regex;
use crate::packet_handle::{FilteredProtocol, Protocol};
use crate::reporter::Reporter;
use crate::sniffer::Sniffer;

#[derive(Debug)]
pub enum ErrorNetworkAnalyser {
    ErrorQuit(String),
    ErrorResume(String),
    ErrorPause(String),
    ErrorNa(String),
    ErrorAbort(String)
}

impl Display for ErrorNetworkAnalyser {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorNetworkAnalyser::ErrorQuit(msg) => write!(f, "{}", msg),
            ErrorNetworkAnalyser::ErrorResume(msg) => write!(f, "{}", msg),
            ErrorNetworkAnalyser::ErrorPause(msg) => write!(f, "{}", msg),
            ErrorNetworkAnalyser::ErrorNa(msg) => write!(f, "{}", msg),
            ErrorNetworkAnalyser::ErrorAbort(msg) => write!(f, "{}", msg)
        }
    }
}

impl Error for ErrorNetworkAnalyser {}

#[derive(PartialEq, Copy, Clone)]
enum StatusValue {
    Running,
    Paused,
    Exit,
}

pub struct Status {
    mutex: Mutex<StatusValue>,
    cvar: Condvar,
}

impl Status {
    pub fn new() -> Status {
        Status {
            mutex: Mutex::new(StatusValue::Running),
            cvar: Condvar::new(),
        }
    }
}


pub struct NetworkAnalyser {
    interface: NetworkInterface,
    time_interval: usize,
    filename: String,
    filter: Filter,
    sniffer_handle: Option<JoinHandle<()>>,
    reporter_handle: Option<JoinHandle<()>>,
    status: Arc<Status>,
    timer_channel: Option<Sender<()>>,
    status_writing: Arc<Mutex<bool>>,
    timer_handle: Option<JoinHandle<()>>
}

impl Display for NetworkAnalyser {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "> NETWORK ANALYSER: \n\n\
                   >> Interface: {}; \n\
                   >> Time Interval: {} secs; \n\
                   >> Filename: '{}'; \n\
                   >> Filter: {};\n", self.interface.name, self.time_interval, self.filename, self.filter)
    }
}

impl NetworkAnalyser {
    pub fn new() -> Self {
        let dft_interface = select_device_by_name(find_my_device_name(0));
        let dft_time_interval = 5;
        let dft_filename = "report.txt".to_string();
        let dft_filter = Filter::new();

        return Self {
            interface: dft_interface,
            time_interval: dft_time_interval,
            filename: dft_filename,
            filter: dft_filter,
            sniffer_handle: None,
            reporter_handle: None,
            status: Arc::new(Status::new()),
            timer_channel: None,
            status_writing: Arc::new(Mutex::new(false)),
            timer_handle: None
        };
    }

    pub fn init(&mut self) -> Result<(), ErrorNetworkAnalyser> {

        println!();
        println!("*************************************************************");
        println!("************  N E T W O R K    A N A L Y S E R  *************");
        println!("*************************************************************");
        println!();
        println!("********************* INITIALIZATION  ***********************");

        // Get interface
        self.interface = get_interface()?;
        self.time_interval = get_time_interval(self.time_interval)?;
        self.filename = get_file_name(&*self.filename)?;
        self.filter= get_filter()?;

        println!();
        println!("*************************************************************");
        println!("{}", self);
        println!("*************************************************************");
        println!();

        return Ok(());
    }

    pub fn start(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        let (_, mut rcv_interface) = match pnet_datalink::channel(&self.interface, pnet_datalink::Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(ErrorNetworkAnalyser::ErrorNa("Error: unhandled channel type".to_string())),
            Err(e) => return Err(ErrorNetworkAnalyser::ErrorNa("unable to create channel".to_owned() + &e.to_string())),
        };

        //thread sniffer
        let (snd_sniffer, rcv_sniffer) = channel();
        let status_sniffer = self.status.clone();
        let interface = self.interface.clone();
        let filter = self.filter.clone();

        self.sniffer_handle = Some(thread::spawn(move || {
            let mut sniffer = Sniffer::new(interface, filter,snd_sniffer, rcv_interface, status_sniffer);
            sniffer.sniffing();
        }));


        let (snd_timer, rcv_timer) = channel();

        //thread timer
        let time_interval = self.time_interval.clone();
        let status_writing = self.status_writing.clone();

        self.timer_channel = Some(snd_timer.clone());
        self.timer_handle = Some(thread::spawn(move || {
            loop {
                match rcv_timer.recv_timeout(Duration::from_secs(time_interval as u64)) {
                    Ok(_) => {
                        break;
                    },
                    Err(err) => {
                        if err == RecvTimeoutError::Timeout {
                            let mut status_writing_value = status_writing.lock().unwrap();
                            *status_writing_value = true;
                        }
                    }
                }
            }
        }));

        //thread reporter
        let status_reporter = self.status.clone();
        let filename = self.filename.clone();
        let time_interval = self.time_interval.clone();
        let status_writing = self.status_writing.clone();

        self.reporter_handle = Some(thread::spawn(move || {
            let mut reporter = Reporter::new(filename, time_interval, status_reporter, rcv_sniffer, snd_timer, status_writing);
            reporter.reporting();
        }));

        println!("**** SNIFFING... ");

        return Ok(());
    }

    pub fn pause(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        let mut status_value = self.status.mutex.lock().unwrap();

        if *status_value == StatusValue::Paused {
            return Err(ErrorNetworkAnalyser::ErrorPause("Error: cannot pause if is already paused".to_string()));
        }
        println!("**** PAUSE ");
        *status_value = StatusValue::Paused;

        return Ok(());
    }


    pub fn quit(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        {
            let mut status_value = self.status.mutex.lock().unwrap();

            // If its in pause mode wakeup the reporter
            if *status_value == StatusValue::Paused
            {
                self.status.cvar.notify_one();
            }
            // Set exit status
            *status_value = StatusValue::Exit;
            println!("**** QUITTING...");
            //self.timer_channel = None;
        }

        if let Some(sniffer_handle) = self.sniffer_handle.take() {
            sniffer_handle.join().unwrap();
        } else {
            return Err(ErrorNetworkAnalyser::ErrorQuit("Error: cannot quit if you don't start".to_string()));
        }

        if let Some(reporter_handle) = self.reporter_handle.take() {
            reporter_handle.join().unwrap();
        } else {
            return Err(ErrorNetworkAnalyser::ErrorQuit("Error: cannot quit if you don't start".to_string()));
        }

        if let Some(timer_handle) = self.timer_handle.take() {
            timer_handle.join().unwrap();
        } else {
            return Err(ErrorNetworkAnalyser::ErrorQuit("Error: cannot quit if you don't start".to_string()));
        }

        println!("************************ THE END  ************************");
        return Ok(());
    }

    pub fn resume(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        let mut status_value = self.status.mutex.lock().unwrap();

        if *status_value == StatusValue::Running {
            return Err(ErrorNetworkAnalyser::ErrorPause("Error: cannot resume if is already running".to_string()));
        }

        *status_value = StatusValue::Running;
        self.status.cvar.notify_one();
        println!("**** SNIFFING RESUMED  ");
        println!("**** SNIFFING...  ");
        return Ok(());
    }
}


/**
Print the name and the description of all the network interfaces found
and returns the total number of interfaces found
 */
fn print_devices() -> usize {
    let interfaces = pnet_datalink::interfaces();
    let tot = interfaces.len();

    for (i, inter) in interfaces.into_iter().enumerate() {
        println!("> {}:   {:?} {:?}", i, inter.name, inter.description);
    }

    return tot;
}

/**
Select a specific network interface given the name
it panics if the name is invalid or if there is no network interface with this name
 */
fn select_device_by_name(name: String) -> NetworkInterface {
    let interfaces = pnet_datalink::interfaces();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name));

    return chosen_interface;
}

fn find_my_device_name(index: usize) -> String {
    return pnet_datalink::interfaces().get(index).unwrap().clone().name;
}




fn get_interface() -> Result<NetworkInterface, ErrorNetworkAnalyser>
{
    println!("> Which of the following interfaces you want to sniff?");
    let tot_interfaces = print_devices();

    let mut my_index_str = String::new();

    loop {
        print!(">> Select an index: [Press X to exit.]  ");
        io::stdout().flush().expect("Error");
        my_index_str.clear();

        match io::stdin().read_line(&mut my_index_str) {
            Ok(_) => {
                let cmd = my_index_str.trim();
                if cmd == "x" || cmd == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }

                match cmd.parse::<usize>() {
                    Ok(my_index) => {
                        if my_index < tot_interfaces {
                            let dev_name = find_my_device_name(my_index);

                            println!("> Ok, you selected:  {:?}", dev_name);
                            let interface = select_device_by_name(dev_name);
                            println!("> Setting the interface in promiscous mode... "); // The promiscous mode is the default configuration (line 167 file lib.rs in pnet-datalink module)
                            return Ok(interface);
                        } else {
                            println!("> [Error]: please select a valid number. Try Again.");
                        }
                    }
                    Err(err) => {
                        println!("> [Error]: {}", err);
                    }
                }
            }
            Err(err) => {
                println!("> [Error]: {}", err);
            }
        }
    }
}

fn get_time_interval(default: usize) -> Result<usize, ErrorNetworkAnalyser>
{
    println!("> Please, insert a time interval. [Press X to exit.] [ENTER to set keep default value of {} ]", default);

    let mut time_interval_str = String::new();


    loop {
        print!(">> Time interval (s): ");
        io::stdout().flush().expect("Error");
        time_interval_str.clear();

        match io::stdin().read_line(&mut time_interval_str) {
            Ok(_) => {
                let cmd = time_interval_str.trim();
                if cmd == "" {
                    return Ok(default);
                }
                else if cmd == "x" || cmd == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }
                else {
                    match cmd.parse::<usize>() {
                        Ok(tmp) => {
                            return Ok(tmp);
                        }
                        Err(err) => println!("> [Error]: {}", err)
                    }
                }
            }
            Err(err) => println!("> [Error]: {}", err)
        }
    }
}

fn get_file_name(default: &str)-> Result<String, ErrorNetworkAnalyser>
{
    println!("> Please, insert the name of the file where we will save the report in \".txt\" format. [Press X to exit.] [Enter to keep the default name: {}]", default);


    let mut filename = String::new();

    loop {
        print!(">> File Name (.txt): ");
        io::stdout().flush().expect("Error");
        filename.clear();

        match io::stdin().read_line(&mut filename) {
            Ok(_) => {
                let cmd = filename.trim();
                if cmd == "" {
                    return Ok(default.to_string());
                }
                else if cmd == "x" || cmd == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }
                else {
                    let reg = Regex::new(r"^[\w,\s-]+\.txt$").unwrap();
                    if reg.is_match(&*cmd) {
                        filename = cmd.to_string();
                        return Ok(filename);
                    } else {
                        println!("> [Error] Please, write a correct filename in txt format! It must not contain :       \\ /:*?\"<>|");
                    }
                }
            }
            Err(err) => {
                println!("> [Error]: {}", err);
            }
        }
    }
}

fn get_filter()-> Result<Filter, ErrorNetworkAnalyser>
{
    println!("> Do you want to set a filter? [Y, N]");

    let mut filt = String::new();
    // Check if the user want the filter
    loop {
        print!(">> Answer: ");
        io::stdout().flush().expect("Error");

        match io::stdin().read_line(&mut filt) {
            Ok(_) => {
                let cmd = filt.trim();
                match cmd {
                    "Y" | "y" => break,
                    "" | "N" | "n" =>  return Ok(Filter::new()),
                    _ => println!("> [Error]: Please, write a correct answer"),
                }
            }
            Err(err) => println!("> [Error]: {}", err)
        }
    }

    let mut filter = Filter::new();
    // Eventually set a filter on the Ip address

    println!("> Filter packets FROM this source ip address: [Press ENTER to skip.] [Press X to exit.]");

    let mut ip_str = String::new();
    loop {
        print!(">> Source Ip Address: ");
        io::stdout().flush().expect("Error");
        ip_str.clear();

        match io::stdin().read_line(&mut ip_str) {
            Ok(_) => {
                ip_str = ip_str.trim().to_string();

                if ip_str == ""  {
                    break;
                }
                else if ip_str == "x" || ip_str == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }

                match validate_ip_address(ip_str.clone()) {
                    Ok(addr) => {
                        filter.set_ip_srg(addr);

                    }
                    Err(err) => println!("Error: {}", err)
                }
            }
            Err(err) => println!("Error: {}", err)
        }
    }

    println!("> Filter packets TO this destination ip address: [Press ENTER to skip.] [Press X to exit.]");
    let mut ip_dst = String::new();

    loop {
        print!(">> Destination Ip Address: ");
        io::stdout().flush().expect("Error");
        ip_dst.clear();
        match io::stdin().read_line(&mut ip_dst) {
            Ok(_) => {
                ip_dst = ip_dst.trim().to_string();

                if ip_dst == "" {
                    break;
                }
                else if ip_dst == "x" || ip_dst== "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }

                match validate_ip_address(ip_dst.clone()) {
                    Ok(addr) => {
                        filter.set_ip_dest(addr);
                        break;
                    }
                    Err(err) => println!("> [Error]: {}", err)
                }
            }
            Err(err) => println!("> [Error]: {}", err)
        }
    }

    println!("> Filter packets coming FROM this port: [Press ENTER to skip.] [Press X to exit.]");
    let mut prt_str = String::new();

    loop {
        print!(">> Source Port: ");
        io::stdout().flush().expect("Error");
        prt_str.clear();

        match io::stdin().read_line(&mut prt_str) {
            Ok(_) => {
                prt_str = prt_str.trim().to_string();

                if prt_str == "" {
                    break;
                }
                else if prt_str == "x" || prt_str == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }

                match prt_str.trim().parse::<u16>() {
                    Ok(val) => {
                        filter.set_prt_srg(val);
                        break;
                    }
                    Err(err) => {
                        println!("> [Error] : {}", err);
                    }
                }
            }
            Err(err) => println!("> [Error]: {}", err)
        }
    }

    println!("> Filter packets going TO this port: [Press ENTER to skip.] [Press X to exit.]");

    let mut prt_dst = String::new();
    loop {
        print!(">> Destination Port: ");
        io::stdout().flush().expect("Error");
        prt_dst.clear();

        match io::stdin().read_line(&mut prt_dst) {
            Ok(_) => {
                prt_dst = prt_dst.trim().to_string();

                if prt_dst == "" {
                    break;

                }
                else if prt_dst == "x" || prt_dst == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }
                match prt_dst.trim().parse::<u16>() {
                    Ok(val) => {
                        filter.set_prt_dest(val);
                        break;
                    }
                    Err(err) => {
                        println!(">[Error] : {}", err);
                    }
                }
            }
            Err(err) => println!(">[Error] : {}", err)
        }
    }


    println!("> Filter on this protocol:  [Press ENTER to skip.] [Press X to exit.]");
    println!("> Possible protocols. Select the index: ");
    let protocols: Vec<FilteredProtocol> = all::<FilteredProtocol>().collect::<Vec<_>>();
    for (ind, tmp) in protocols.iter().enumerate() {
        println!("> {}: {}", ind, tmp);
    }

    let mut cmd = String::new();
    loop {
        print!(">> Selected Index: ");
        io::stdout().flush().expect("Error");
        cmd.clear();

        match io::stdin().read_line(&mut cmd) {
            Ok(_) => {
                cmd = cmd.trim().to_string();

                if cmd == "" {
                    break;
                }
                else if prt_str == "x" || prt_str == "X"
                {
                    return Err(ErrorNetworkAnalyser::ErrorAbort("> [Error]: User asked to abort.".to_string()));
                }

                match cmd.parse::<usize>() {
                    Ok(val) => {
                        if val < protocols.len() {
                            let protocol = protocols[val].to_string().parse::<Protocol>();
                            match protocol {
                                Ok(p) => {
                                    filter.set_protocol(p);
                                    break;
                                }
                                Err(err) => {
                                    println!("[Error]: {:?}", err)
                                }
                            }
                        } else {
                            println!(">[Error]: wrong number");
                        }
                    }
                    Err(err) => println!(">[Error]: {}", err)
                }
            }
            Err(err) => println!(">[Error]: {}", err)
        }
    }

    return Ok(filter);

}






fn validate_ip_address(ip_str: String) -> Result<IpAddr, String> {
    let vec_ip4: Vec<&str> = ip_str.split(".").map(|x| x).collect();
    let vec_ip6: Vec<&str> = ip_str.split(":").map(|x| x).collect();
    let mut error = String::new();
    if vec_ip4.len() == 4 {
        let mut correct = true;
        let mut tmp: Vec<u8> = vec![0; 4];
        for i in 0..4 {
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
    } else if vec_ip6.len() == 8 {
        let mut correct = true;
        let mut tmp: Vec<u16> = vec![0; 8];
        for i in 0..8 {
            match vec_ip6[i].parse::<u16>() {
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
