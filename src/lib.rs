mod packet_handle;
mod sniffer;
mod reporter;

use pcap::{Active, Capture, Device};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel};
use packet_handle::{Filter};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime};
use regex::Regex;
use crate::packet_handle::{Protocol};
use crate::reporter::Reporter;
use crate::sniffer::Sniffer;


#[derive(Debug)]
/// Possible errors that may be generated while using the NetworkAnalyser
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

#[derive(PartialEq, Copy, Clone, Debug)]
/// Possible status of the application
enum StatusValue {
    Running,
    Paused,
    Exit,
}
/// Status of the application (sharable by more threads)
pub struct Status {
    mutex: Mutex<StatusValue>,
    cvar: Condvar,
}

impl Status {
    /// Function to create a new instance of the Status object
    pub fn new() -> Status {
        Status {
            mutex: Mutex::new(StatusValue::Running),
            cvar: Condvar::new(),
        }
    }
}

/// NetworkAnalyser object. It manages all the sniffing process by creating two threads: the Sniffer and the Reporter.
/// The user can control the process by using the functions pause(), resume(), quit()
pub struct NetworkAnalyser {
    interface: Device,
    time_interval: usize,
    filename: String,
    final_filename: String,
    filter: Filter,
    sniffer_handle: Option<JoinHandle<()>>,
    reporter_handle: Option<JoinHandle<()>>,
    status: Arc<Status>,
}

impl Display for NetworkAnalyser {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "> NETWORK ANALYSER: \n\n\
                   >> Interface: {}; \n\
                   >> Time Interval: {} secs; \n\
                   >> Filename: '{}'; \n\
                   >> Final Filename: '{}'; \n\
                   >> Filter: {};\n", self.interface.name, self.time_interval,
                                      self.filename, self.final_filename, self.filter)
    }
}

impl NetworkAnalyser {
    /// Create a new instance of the NetworkAnalyser and set default values to its fields
    /// - Network Interface: selected the first one.
    /// - Time interval: 5 sec
    /// - Report file name: "report.txt"
    /// - Final report file name: "final_report.txt"
    /// - Filter: empty. No filter
    pub fn new() -> Self {
        let dft_interface = select_device_by_name(find_my_device_name(0));
        let dft_time_interval = 5;
        let dft_filename = "report.txt".to_string(); //default report file
        let dft_final_filename = "final_report.txt".to_string(); //default final report file
        let dft_filter = Filter::new();

        return Self {
            interface: dft_interface,
            time_interval: dft_time_interval,
            filename: dft_filename,
            final_filename: dft_final_filename,
            filter: dft_filter,
            sniffer_handle: None,
            reporter_handle: None,
            status: Arc::new(Status::new()),
        };
    }

    /// Function used to initialise the Network Analyser with custom values.
    /// If an error occours it returns an ErrorNetworkAnalyser describing what happen.
    /// Otherwise it returns void.
    pub fn init(&mut self) -> Result<(), ErrorNetworkAnalyser> {

        println!();
        println!("************************************************************************************************************************************************");
        println!("*****************************************************  N E T W O R K    A N A L Y S E R  *******************************************************");
        println!("************************************************************************************************************************************************");
        println!();
        println!("**************************************************************** INITIALIZATION  ***************************************************************");

        // Get interface
        self.interface = get_interface()?;
        self.time_interval = get_time_interval(self.time_interval)?;
        self.filename = get_file_name(&*self.filename)?;
        self.final_filename = self.filename.clone();
        self.final_filename.insert_str(0, "final_");

        self.filter= get_filter()?;

        println!();
        println!("************************************************************************************************************************************************");
        println!("{}", self);
        println!("************************************************************************************************************************************************");
        println!();

        return Ok(());
    }

    /// Start the NetworkAnalyser.
    /// It can return an ErrorNetworkAnalyser if an error occours during the process.
    /// Otherwise it returns void and it means that the process is running.
    pub fn start(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        let rcv_channel = activate_capture(&self.interface)?;

        // Record initial time
        let time = SystemTime::now();

        // Thread Sniffer
        // - Create a channel shared by the sniffer and the reporter
        let (snd_sniffer, rcv_sniffer) = channel();
        // - Clone the status, creating a copy of the pointer
        let status_sniffer = self.status.clone();
        // - Clone the network interface pointer. It will be used by the sniffer to get packets from the interface
        let interface = self.interface.clone();
        // - Clone the filter (needed by the sniffer to accordingly filter the packets)
        let filter = self.filter.clone();
        // - Clone the initial time
        let time_sniffer = time.clone();

        // Run the thread sniffer
        self.sniffer_handle = Some(thread::spawn(move || {
            let sniffer = Sniffer::new(interface, filter,snd_sniffer, rcv_channel, status_sniffer, time_sniffer);
            sniffer.sniffing();
        }));

        // Thread Reporter
        // - Clone the status, creating a copy of the pointer
        let status_reporter = self.status.clone();
        // - Clone the name of the file for the report
        let filename = self.filename.clone();
        // - Clone the name of the file for the final report
        let final_filename = self.final_filename.clone();
        // - Clone the time interval
        let time_interval = self.time_interval.clone();
        // - Clone the initial time
        let time_reporter = time.clone();
        // Run the reporter thread
        self.reporter_handle = Some(thread::spawn(move || {
            let reporter = Reporter::new(
                filename,
                final_filename,
                time_interval,
                status_reporter,
                rcv_sniffer,

                time_reporter,
                filter);
            reporter.reporting();

        }));

        println!("**** SNIFFING... ");

        return Ok(());
    }
    /// Pause the network analyser
    /// If the process is already in 'Pause' mode then it returns an error.
    pub fn pause(&mut self) -> Result<(), ErrorNetworkAnalyser> {
        let mut status_value = self.status.mutex.lock().unwrap();

        if *status_value == StatusValue::Paused {
            return Err(ErrorNetworkAnalyser::ErrorPause("Error: cannot pause if is already paused".to_string()));
        }
        println!("**** PAUSE ");
        *status_value = StatusValue::Paused;

        return Ok(());
    }

    /// Quit the process.
    /// It puts the application in 'Exit' state.
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

        println!("***** You can find the final report here: {}", self.final_filename);
        println!("************************ THE END  ************************");
        return Ok(());
    }

    /// Resume the process. It wakes up the Reporter and the Sniffer and the process continues.
    /// It returns an error if the process is already running.
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



/// Print the names and the descriptions of all the network interfaces found
/// and returns the total number of interfaces found
/// if an error occurs, it returns an instance of ErrorNetworkAnalyser!
fn print_devices() -> Result<usize, ErrorNetworkAnalyser> {

    let interfaces = match Device::list(){
        Ok(_interfaces) => _interfaces,
        Err(err) => return Err(ErrorNetworkAnalyser::ErrorNa(err.to_string()))
    };

    let tot = interfaces.len();

    for (i, inter) in interfaces.into_iter().enumerate() {
        println!("> {}:   {:?} {:?}", i, inter.name, inter.desc.unwrap_or_else(|| "-".to_string()));
    }

    return Ok(tot);
}


///Select a specific network interface given the name
///it panics if the name is invalid or if there is no network interface with this name
fn select_device_by_name(name: String) -> Device {
    let interfaces = Device::list().unwrap();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name)); // this status should not be reachable

    return chosen_interface;
}

/// given the index of the device in the devices list, it returns its name
fn find_my_device_name(index: usize) -> String {
    let list: Vec<Device> = Device::list().unwrap();
    return list[index].name.clone();
}



/// It asks the user to select the Device she/he wants to sniff.
/// If an error occurs it returns an ErrorNetworkAnalyser, otherwise it returns the Device
fn get_interface() -> Result<Device, ErrorNetworkAnalyser>
{
    println!("> Which of the following interfaces you want to sniff?");
    let tot_interfaces = print_devices()?;

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
                            println!("> Setting the interface in promiscous mode... ");
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

/// It asks the user to select how often (seconds) he/she wants the report to be updated
/// If an error occours it returns an ErrorNetworkAnalyser, otherwise it returns the time_interval
fn get_time_interval(default: usize) -> Result<usize, ErrorNetworkAnalyser>
{
    println!("> Please, insert a time interval. We will update the report every 'time_interval' seconds. [Press X to exit.] [ENTER to set keep default value of {} ]", default);

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


/// It asks the user to select the name of the file where the report needs to be written.
/// If an error occours it returns an ErrorNetworkAnalyser, otherwise it returns the filename
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

/// It asks the user to select the Filter she/he wants to add to the sniffing process.
/// If an error occours it returns an ErrorNetworkAnalyser, otherwise it returns the Filter
fn get_filter()-> Result<Filter, ErrorNetworkAnalyser>
{
    println!("> Do you want to set a filter? [Y, N]");

    let mut filt = String::new();
    let mut filter = Filter::new();
    // Check if the user want the filter
    loop {
        print!(">> Answer: ");
        io::stdout().flush().expect("Error");

        match io::stdin().read_line(&mut filt) {
            Ok(_) => {
                let cmd = filt.trim();
                match cmd {
                    "Y" | "y" => break,
                    "" | "N" | "n" =>  return Ok(filter),
                    _ => println!("> [Error]: Please, write a correct answer"),
                }
            }
            Err(err) => println!("> [Error]: {}", err)
        }
    }

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
                        break;

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
    let protocols: Vec<Protocol> = vec![
        Protocol::Ethernet,
        Protocol::Arp,
        Protocol::IpV4,
        Protocol::IpV6,
        Protocol::Udp,
        Protocol::Tcp,
        Protocol::IcmpV4,
        Protocol::IcmpV6,
        Protocol::Dns,
        Protocol::Tls,
        Protocol::Http,
        Protocol::Https,
        Protocol::None
    ];
    for (ind, tmp) in protocols.iter().enumerate() {
        if *tmp != Protocol::None { println!("> {}: {}", ind, tmp); }
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
                        if val < protocols.len() - 1 {
                            filter.set_protocol(protocols[val]);
                            break;
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





/// It returns true if ip_str is a valide ip address, false otherwise
fn validate_ip_address(ip_str: String) -> Result<IpAddr, String> {
    let vec_ip4: Vec<&str> = ip_str.split(".").map(|x| x).collect();
    let vec_ip6: Vec<&str> = ip_str.split(":").map(|x| x).collect();

    if vec_ip4.len() == 4 {
        let mut correct = true;
        let mut tmp: Vec<u8> = vec![0; 4];
        for i in 0..4 {
            match vec_ip4[i].parse::<u8>() {
                Ok(val) => {
                    tmp[i] = val;
                }
                Err(_) => {
                    correct = false;

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
                Err(_) => {
                    correct = false;

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

/// Given a device, it returns the Channel from which the sniffer gets the level2 packets.
/// also, it sets the interface in promiscous mode,
/// the capture as an online and non blocking capture
pub fn activate_capture(device: &Device) -> Result<Capture<Active>, ErrorNetworkAnalyser>{

    let mut cap = match Capture::from_device(device.clone()){
        Ok(cap) => cap,
        Err(err) => return Err(ErrorNetworkAnalyser::ErrorNa(err.to_string()))
    };
    cap = cap.promisc(true);

    let act_cap = match cap.open() {
        Ok(act) => act,
        Err(err) => return Err(ErrorNetworkAnalyser::ErrorNa(err.to_string()))
    };

    let non_block = match act_cap.setnonblock(){
        Ok(n_blk) => n_blk,
        Err(err) => return Err(ErrorNetworkAnalyser::ErrorNa(err.to_string()))
    };

    return Ok(non_block);
}
