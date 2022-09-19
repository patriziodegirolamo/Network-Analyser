extern crate pnet;

use pnet_datalink::{self as datalink, NetworkInterface};
use std::io::{self, Write};
use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use crate::{packet_handle, PacketInfo};
use crate::packet_handle::{Filter, FilterEnum};


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
    println!("{:?}", filter);

    //da testare mancano dns, icmp4, icmp6
    //protocolli da filtrare sono Dns, Tls, Tcp, Udp, IcmpV4, IcmpV6, Arp
    //filter.set_protocol(Protocol::Arp);
    //filter.ip_dest = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 106)));
    //filter.prt_dest = Some(443);
    return (interface, time_interval, filename, filter);
}

pub fn init_sniffing() -> (NetworkInterface, usize, String, Filter)
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
    println!("> Please, insert a time interval. [Press X to exit]");

    let mut time_interval = 0;

    loop {
        print!("> Time interval (s): ");
        io::stdout().flush().expect("Error");

        let mut time_interval_str = String::new();

        if io::stdin().read_line(&mut time_interval_str).is_ok()
        {
            let cmd = time_interval_str.trim();
            if cmd == "X" || cmd == "x"
            {
                println!("Closing.....");
                break;
            } else if cmd.parse::<usize>().is_ok()
            {
                time_interval = cmd.parse::<usize>().unwrap();
                if time_interval > 0
                {
                    break;
                }
            }
        }
        println!("> Error: please select a valid number. Try Again.");
    }

    println!();
    // select file name + check file name
    println!("> Please, insert the name of the file where we will save the report. [Press X to exit] ");
    let mut filename = String::new();

    loop {
        print!("> File Name (.txt file): ");
        io::stdout().flush().expect("Error");

        if io::stdin().read_line(&mut filename).is_ok()
        {
            let cmd = filename.trim();
            if cmd == "X" || cmd == "x"
            {
                println!("Closing.....");
                break;
            } else if cmd.ends_with(".txt")
            {
                filename = cmd.to_string();
                break;
            }
        }
        println!("> Error. Try Again.");
    }

    println!();

    // select filtri + check filters
    let mut filter_cmd = false;

    println!("> Do you want to add a filter (Y/N)?  [Press X to Exit] ");
    let mut filter = Filter::new();
    let filters_enum = [FilterEnum::IpSorg, FilterEnum::PortSorg, FilterEnum::IpDest, FilterEnum::PortDest, FilterEnum::IsoOsiProtocol];

    loop {
        print!("> Command: ");
        io::stdout().flush().expect("Error");
        let mut cmd = String::new();
        if io::stdin().read_line(&mut cmd).is_ok()
        {
            match cmd.trim()
            {
                "X" | "x" => {
                    println!("Closing.....");
                    break;
                }
                "N" | "n" => {
                    filter_cmd = false;
                    break;
                }
                "Y" | "y" => {
                    filter_cmd = true;
                    break;
                }

                _ => { continue; }
            }

            //println!("> Invalid Command. Try Again.");
        }
    }

    if filter_cmd {
        // Create a filter
        println!("> Specify the filter fields. For each field insert the value or '_' to skip it.");
        for field in filters_enum
        {
            filter.populate(field);
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
