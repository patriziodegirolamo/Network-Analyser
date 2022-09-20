extern crate pnet;

use pnet_datalink::{self as datalink, NetworkInterface};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use enum_iterator::{all};
use crate::{packet_handle, PacketInfo};
use crate::packet_handle::{Filter, FilteredProtocol, Protocol};


/*
*  INITIALIZATION FUNCTIONS
*
*/

/**
Print the name and the description of all the network interfaces found
and returns the total number of interfaces found
 */
pub fn print_devices() -> usize {
    let interfaces = datalink::interfaces();
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
    let interfaces = datalink::interfaces();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name));

    return chosen_interface;
}

pub fn find_my_device_name(index: usize) -> String {
    return datalink::interfaces().get(index).unwrap().clone().name;
}

pub fn fast_init_sniffing() -> (NetworkInterface, usize, String, Filter)
{   //TODO: handle the closing!!!!!
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
    println!();
    println!("> Which of the following interfaces you want to sniff? [Press X to exit]");
    println!();
    let tot_interfaces = print_devices();
    println!();
    let mut my_index = 0;

    loop {
        print!("> Select an index: ");
        io::stdout().flush().expect("Error");

        let mut my_index_str = String::new();

        if io::stdin().read_line(&mut my_index_str).is_ok()
        {
            let cmd = my_index_str.trim();
            if cmd == "X" || cmd == "x"
            {
                println!("Closing.....");
                break;
            } else if cmd.parse::<usize>().is_ok()
            {
                my_index = cmd.parse::<usize>().unwrap();
                if my_index < tot_interfaces
                {
                    break;
                }
            }
        }
        println!("> Error: please select a valid number. Try Again.");
    }

    let dev_name = find_my_device_name(my_index);
    println!("> Ok, you selected:  {:?}", dev_name);
    let interface = select_device_by_name(dev_name);
    println!("> Setting the interface in promiscous mode... "); // The promiscous mode is the default configuration (line 167 file lib.rs in pnet-datalink module)
    println!();
    let mut time_interval = 0;
    let mut filename = "report.txt".to_string();
    let mut filter = Filter::new();

    //da testare mancano dns, icmp4, icmp6
    //protocolli da filtrare sono Dns, Tls, Tcp, Udp, IcmpV4, IcmpV6, Arp
    //filter.set_protocol(Protocol::Tcp);
    //filter.ip_dest = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 106)));
    //filter.prt_dest = Some(443);
    println!("{:?}", filter);
    return (interface, time_interval, filename, filter);
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
    Running,
    Paused,
}
pub fn init_sniffing() -> (NetworkInterface, usize, String, Filter) {
    let mut state = State::Index;
    let mut my_index = 0;
    let mut interface = select_device_by_name(find_my_device_name(my_index));
    let mut time_interval = 1;
    let mut filename = "report.txt".to_string();
    let mut filter = Filter::new();

    //TODO: handle the closing!!!!!
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
                        if cmd == "E" || cmd == "e" {
                            println!("Closing the current analysis.....");
                            state = State::Index;
                        }
                        else if cmd == ""{
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
                println!("> Please, insert the name of the file where we will save the report. By default is \"report.txt\" [Press E to exit] ");

                io::stdout().flush().expect("Error");

                match io::stdin().read_line(&mut filename) {
                    Ok(_) => {
                        let cmd = filename.trim();
                        if cmd == "E" || cmd == "e" {
                            println!("Closing.....");
                            state = State::Index;
                        }
                        else if cmd == ""{
                            state = State::Filter
                        }
                        else{
                            let file_name_vec :Vec<&str> = cmd.split(".").map(|x| x).collect();
                            match file_name_vec.len() {
                                0 => {
                                    println!("Error, something was wrong!");
                                }
                                1 => {
                                    //ci aggiungo il txt
                                    filename = cmd.to_owned() + ".txt";
                                }
                                2 => {
                                    //se l'estensione non va bene ci metto txt
                                    if file_name_vec.last().unwrap().to_string() != ".txt".to_string(){
                                        println!("non va bene, te lo modifico in \"{}.txt\"", file_name_vec[0]);
                                        filename = file_name_vec[0].to_owned() + ".txt";
                                    }
                                }
                                _ => {
                                    //ci metto il txt al posto dell' estensione
                                    println!("ESTENSIONE NON SUPPORTATA, te lo modifico in \"{}.txt\"", file_name_vec[0]);
                                    filename = file_name_vec[0].to_owned() + ".txt";
                                }
                            }
                            state = State::Filter;
                        }
                    }
                    Err(err) => {
                        println!("Error: {}", err);
                    }
                }
            }
            State::Filter => {
                println!("do you want to add a filter? [Y, N]");
                io::stdout().flush().expect("Error");

                let mut filt = String::new();
                if io::stdin().read_line(&mut filt).is_ok() {
                    let cmd = filt.trim();
                    if cmd == "Y" || cmd == "y" {
                        state = State::IpSorg;
                        continue;
                    }
                    if cmd == "N" || cmd == "n" {
                        state = State::Running;
                        continue;
                    }
                    else {
                        continue;
                    }
                }
            }
            State::IpSorg => {
                println!("please insert the source ip address or X otherwise");
                let mut ip_str = String::new();
                if io::stdin().read_line(&mut ip_str).is_ok() {
                    ip_str = ip_str.trim().to_string();

                    if ip_str == "X" || ip_str == "x"{
                        state = State::IpDest;
                        continue;
                    }

                    let vec_ip4 : Vec<&str> = ip_str.split(".").map(|x| x).collect();
                    let vec_ip6 : Vec<&str> = ip_str.split(":").map(|x| x).collect();

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
                                    println!("ERROR {}", e);
                                }
                            }
                        }
                        if correct {
                            filter.set_ip_srg(IpAddr::V4(Ipv4Addr::new(tmp[0], tmp[1], tmp[2], tmp[3])));
                            println!("{:?}", filter);
                            state = State::IpDest;
                            continue;
                        }
                    }
                    if vec_ip6.len() == 8 {
                        let mut correct = true;
                        let mut tmp : Vec<u16> = vec![0; 8];
                        for i in 0..8{
                            match vec_ip6[i].parse::<u16>(){
                                Ok(val) => {
                                    tmp[i] = val;
                                }
                                Err(e) => {
                                    correct = false;
                                    println!("ERROR {}", e);
                                }
                            }
                        }
                        if correct {
                            filter.set_ip_srg(IpAddr::V6(Ipv6Addr::new(tmp[0], tmp[1], tmp[2], tmp[3],
                                                                       tmp[4], tmp[5], tmp[6], tmp[7])));
                            state = State::IpDest;
                            println!("{:?}", filter);
                            continue;
                        }
                    }
                    println!("the ip address is not correct!");
                }
            }
            State::IpDest => {
                println!("please insert the destination ip address or X otherwise");
                let mut ip_str = String::new();
                if io::stdin().read_line(&mut ip_str).is_ok() {

                    ip_str = ip_str.trim().to_string();

                    if ip_str == "X" || ip_str == "x"{
                        state = State::PortaSorg;
                        continue;
                    }
                    let vec_ip4 : Vec<&str> = ip_str.split(".").map(|x| x).collect();
                    let vec_ip6 : Vec<&str> = ip_str.split(":").map(|x| x).collect();

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
                                    println!("ERROR {}", e);
                                }
                            }
                        }
                        if correct {
                            filter.set_ip_dest(IpAddr::V4(Ipv4Addr::new(tmp[0], tmp[1], tmp[2], tmp[3])));
                            println!("{:?}", filter);
                            state = State::PortaSorg;
                            continue;
                        }
                    }
                    if vec_ip6.len() == 8 {
                        let mut correct = true;
                        let mut tmp : Vec<u16> = vec![0; 8];
                        for i in 0..8{
                            match vec_ip6[i].parse::<u16>(){
                                Ok(val) => {
                                    tmp[i] = val;
                                }
                                Err(e) => {
                                    correct = false;
                                    println!("ERROR {}", e);
                                }
                            }
                        }
                        if correct {
                            filter.set_ip_dest(IpAddr::V6(Ipv6Addr::new(tmp[0], tmp[1], tmp[2], tmp[3],
                                                                       tmp[4], tmp[5], tmp[6], tmp[7])));
                            state = State::PortaSorg;
                            println!("{:?}", filter);
                            continue;
                        }
                    }

                    println!("the ip address is not correct!");
                }


            }
            State::PortaSorg => {
                println!("please insert the source port number or X otherwise");
                let mut prt_str = String::new();
                if io::stdin().read_line(&mut prt_str).is_ok() {
                    prt_str = prt_str.trim().to_string();

                    if prt_str == "X" || prt_str == "x"{
                        state = State::PortaDest;
                        continue;
                    }

                    match prt_str.trim().parse::<u16>(){
                        Ok(val) => {
                            filter.set_prt_srg(val);
                            state = State::PortaDest;
                        }
                        Err(e) => {
                            println!("ERror : {}", e);
                        }
                    }
                }
            }
            State::PortaDest => {
                println!("please insert the destination port number or X otherwise");
                let mut prt_str = String::new();
                if io::stdin().read_line(&mut prt_str).is_ok() {
                    prt_str = prt_str.trim().to_string();

                    if prt_str == "X" || prt_str == "x"{
                        state = State::Protocol;
                        continue;
                    }

                    match prt_str.trim().parse::<u16>(){
                        Ok(val) => {
                            filter.set_prt_dest(val);
                            state = State::Protocol;
                        }
                        Err(e) => {
                            println!("ERror : {}", e);
                        }
                    }
                }
            }
            State::Protocol => {
                println!("scegli tra uno dei seguenti protocolli o X");
                let protocols :Vec<FilteredProtocol>= all::<FilteredProtocol>().collect::<Vec<_>>();
                for (ind, tmp) in protocols.iter().enumerate(){
                    println!("{}: {}", ind, tmp);
                }
                let mut cmd = String::new();
                if io::stdin().read_line(&mut cmd).is_ok() {
                    cmd = cmd.trim().to_string();

                    if cmd == "X" || cmd == "x" {
                        state = State::Running;
                        continue;
                    }

                    match cmd.parse::<usize>(){
                        Ok(val) => {
                            if val < protocols.len(){
                                println!("protocollo = {}", protocols[val]);
                                let protocol = protocols[val].to_string().parse::<Protocol>();
                                match protocol{
                                    Ok(p) => {
                                        filter.set_protocol(p);
                                        state = State::Running;
                                        println!("Filtro: {:?}", filter);
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
            }
            State::Running => {
                break;
            }
            State::Paused => {
                break;
            }

        }
    }

    return (interface, time_interval, filename, filter);
}

pub fn handle_particular_interfaces(interface: &NetworkInterface, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) -> bool {
    let mut buf: [u8; 1600] = [0u8; 1600]; //il frame ethernet è di 1518 byte -> sovradimensionato a 1600
    let mut new_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
    let payload_offset;
    if cfg!(any(target_os = "macos", target_os = "ios"))
        && interface.is_up()
        && !interface.is_broadcast()
        && ((!interface.is_loopback() && interface.is_point_to_point())
        || interface.is_loopback())
    {
        if interface.is_loopback() {
            // The pnet code for BPF loopback adds a zero'd out Ethernet header
            payload_offset = 14;
        } else {
            // Maybe is TUN interface
            payload_offset = 0;
        }
        if packet.len() > payload_offset {
            let version = Ipv4Packet::new(&packet[payload_offset..]).unwrap().get_version();

            if version == 4 {
                println!("CASO PARTICOLARE 1");
                new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                new_ethernet_frame.set_payload(&packet[payload_offset..]);
                packet_handle::handle_ethernet_frame(&new_ethernet_frame.to_immutable(), new_packet_info, &filter);
                return true;
            } else if version == 6 {
                println!("CASO PARTICOLARE 2");
                new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                new_ethernet_frame.set_payload(&packet[payload_offset..]);
                packet_handle::handle_ethernet_frame(&new_ethernet_frame.to_immutable(), new_packet_info, &filter);
                return true;
            }
        }
    }
    return false;
}
