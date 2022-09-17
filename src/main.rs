// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example shows a basic packet logger using libpnet
extern crate pnet;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use pnet_datalink::{self as datalink, NetworkInterface};
use pnet::packet::arp::{ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet_datalink::Channel::Ethernet as Ethernet;

//use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};
use prettytable::{Attr, Cell, Row, Table};

#[macro_use]
extern crate prettytable;

//use std::process;

/*
*  INITIALIZATION FUNCTIONS
*
*/


/**
Print the name and the description of all the network interfaces found
and returns the total number of interfaces found
 */
fn print_devices() -> usize {
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
fn select_device_by_name(name: String) -> NetworkInterface {
    let interfaces = datalink::interfaces();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name));

    return chosen_interface;
}

fn find_my_device_name(index: usize) -> String {
    return datalink::interfaces().get(index).unwrap().clone().name;
}

fn fast_init_sniffing() -> (NetworkInterface, usize, String, Filter)
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

fn init_sniffing() -> (NetworkInterface, usize, String, Filter)
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
/*
*  PRINT on FiLE FUNCTIONS
*
*/

use std::fs::{File};
use std::ops::Deref;
use std::str::FromStr;
use dns_parser::rdata::Opt;
use pnet::datalink::{ChannelType, Config};
use crate::Protocol::IpV4;

fn open_file(filename: String) -> io::Result<File> {
    return File::options().write(true).truncate(true).create(true).open(filename);
}

fn write_summaries(file: &mut File, convs_summaries: HashMap<ConversationKey, ConversationStats>) {

    // Create the table
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("Ip_srg").style_spec("b"),
        Cell::new("Prt_srg").style_spec("b"),
        Cell::new("Ip_dest").style_spec("b"),
        Cell::new("Prt_dest").style_spec("b"),
        Cell::new("Protocol").style_spec("b"),
        Cell::new("Tot_bytes").style_spec("b"),
        Cell::new("starting_time (nano_s)").style_spec("b"),
        Cell::new("ending_time (nano_s)").style_spec("b"),
    ]));


    for (key, elem) in &convs_summaries {
        table.add_row(Row::new(vec![
            Cell::new(&*key.ip_srg.to_string()), // s  : String -> *s : str (via Deref<Target=str>) -> &*s: &str
            Cell::new(&*key.prt_srg.to_string()),
            Cell::new(&*key.ip_dest.to_string()),
            Cell::new(&*key.prt_dest.to_string()),
            Cell::new(&*key.protocol.to_string()),
            Cell::new(&*elem.tot_bytes.to_string()),
            Cell::new(&*elem.starting_time.unwrap().as_nanos().to_string()),
            Cell::new(&*elem.ending_time.unwrap().as_nanos().to_string()),
        ]));
    }

    // Print the table on file
    table.print(file).expect("Error");
}

/*
*  PROTOCOLS HANDLE FUNCTIONS
*
*/

fn handle_dns_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    if dns_parser::Packet::parse(packet).is_ok() {
        PacketInfo::set_protocol(new_packet_info, Protocol::Dns);

        if filter.protocol != Protocol::None && filter.protocol != Protocol::Dns{
            new_packet_info.set_not_printed();
        }

        if new_packet_info.printed {
            println!(
                "DNS Packet: {}:{} > {}:{}",
                new_packet_info.ip_sorg.unwrap(),
                new_packet_info.prt_sorg,
                new_packet_info.ip_dest.unwrap(),
                new_packet_info.prt_dest,
            );
        }
    }
}

fn handle_tls_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) -> bool {
    return if tls_parser::parse_tls_plaintext(packet).is_ok() || tls_parser::parse_tls_encrypted(packet).is_ok() {
        PacketInfo::set_protocol(new_packet_info, Protocol::Tls);

        if filter.protocol != Protocol::None && filter.protocol != Protocol::Tls {
            new_packet_info.set_not_printed();
        }

        if new_packet_info.printed {
            println!(
                "TLS Packet: {}:{} > {}:{}",
                new_packet_info.ip_sorg.unwrap(),
                new_packet_info.prt_sorg,
                new_packet_info.ip_dest.unwrap(),
                new_packet_info.prt_dest,
            );
        }
        true
    } else {
        false
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        // Extract the source and destination port
        let prt_srg = udp.get_source();
        let prt_dest = udp.get_destination();

        // Save them in the PacketInfo structure

        //se esiste il filtro ed è diverso dalla porta sorgente
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg{
            new_packet_info.set_not_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest{
            new_packet_info.set_not_printed();
        }

        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Udp);
        if prt_srg == 53 || prt_dest == 53 {
            handle_dns_packet(udp.payload(), new_packet_info, filter);
        }
        else if new_packet_info.printed{
            if filter.protocol == Protocol::None || filter.protocol == Protocol::Udp{
                println!(
                    "UDP Packet: {}:{} > {}:{}; length: {}",
                    source,
                    prt_srg,
                    destination,
                    prt_dest,
                    udp.get_length()
                );
            }
        }

    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmp_packet = IcmpPacket::new(packet);

    if let Some(icmp_packet) = icmp_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV4);
        if filter.protocol != Protocol::IcmpV4 || filter.protocol != Protocol::IcmpV4{
            new_packet_info.set_not_printed();
        }
        if new_packet_info.printed{
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    println!(
                        "ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    println!(
                        "ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                }
                _ => println!(
                    "ICMP packet {} -> {} (type={:?})",
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                ),
            }
        } else {

        }
    } else {
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmpv6_packet = Icmpv6Packet::new(packet);

    if let Some(icmpv6_packet) = icmpv6_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV6);
        if filter.protocol != Protocol::IcmpV6 || filter.protocol != Protocol::IcmpV6{
            new_packet_info.set_not_printed();
        }

        else if new_packet_info.printed{
            println!(
                "ICMPv6 packet {} -> {} (type={:?})",
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
        }
    } else {
        println!("Malformed ICMPv6 Packet");
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        // Extract the source and destination ports
        let prt_srg = tcp.get_source();
        let prt_dest = tcp.get_destination();

        //se esiste il filtro ed è diverso dalla porta sorgente
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg{
            new_packet_info.set_not_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest{
            new_packet_info.set_not_printed();
        }

        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Tcp);
        // Check if the protocol carried is TLS

        if prt_srg == 53 || prt_dest == 53 {
            handle_dns_packet(tcp.payload(), new_packet_info, filter);
        }

        else if handle_tls_packet(tcp.payload(), new_packet_info, filter){
        }

        else if new_packet_info.printed{
            if filter.protocol == Protocol::None || filter.protocol == Protocol::Tcp {
                println!(
                "TCP Packet: {}:{} > {}:{}; length: {}",
                source,
                prt_srg,
                destination,
                prt_dest,
                packet.len()
                );
            }
        }

    } else {
        println!("Malformed TCP Packet");
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr, protocol: IpNextHeaderProtocol, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            //se il protocollo è udp ma il filtro è diverso da udp, dns o none -> il pacchetto va filtrato
            match filter.protocol {
                Protocol::Udp => {}
                Protocol::Dns => {}
                Protocol::None => {}
                _ => {new_packet_info.set_not_printed()}
            }
            handle_udp_packet(source, destination, packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Tcp => {
            //se il protocollo è tcp ma il filtro è diverso da tcp, tls, dns o none -> il pacchetto va filtrato
            match filter.protocol {
                Protocol::Tls => {}
                Protocol::Tcp => {}
                Protocol::Dns => {}
                Protocol::None => {}
                _ => {new_packet_info.set_not_printed();}
            }
            handle_tcp_packet(source, destination, packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Icmp => {
            //se il protocollo non è icmp -> va filtrato
            if filter.protocol != Protocol::IcmpV4{
                new_packet_info.set_not_printed();
            }
            handle_icmp_packet(source, destination, packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            //se il protocollo non è icmp -> va filtrato
            if filter.protocol != Protocol::IcmpV6{
                new_packet_info.set_not_printed();
            }
            handle_icmpv6_packet(source, destination, packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Ipv4 => {
            println!("IP over IP")
        }
        _ => {
            /*
            if filter.protocol == Protocol::None {
                println!(
                    "Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                    match source {
                        IpAddr::V4(..) => "IPv4",
                        _ => "IPv6",
                    },
                    source,
                    destination,
                    protocol,
                    packet.len()
                )
            }

             */
        }
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    let header = Ipv4Packet::new(ethernet.payload());

    if let Some(header) = header {
        //la dimensione dell'header ip è di 5 -> Ipv4Packet::get_header_length(&header)
        //questo numero 5 è un i32
        //dim i32 -> 4Bytes
        //dim effettiva dell'header -> 20 bytes
        //println!("IPV4 header: {}, IPV4 payload: {}", Ipv4Packet::get_header_length(&header), header.payload().len());
        // Extract the source and destination ip address
        let ip_sorg = IpAddr::V4(header.get_source());
        let ip_dest = IpAddr::V4(header.get_destination());

        // Save them in the Packet Info structure

        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg{
            new_packet_info.set_not_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
            new_packet_info.set_not_printed();
        }

        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        handle_transport_protocol(
            ip_sorg,
            ip_dest,
            header.get_next_level_protocol(),
            header.payload(),
            new_packet_info,
            filter,
        );
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ipv6_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    let header = Ipv6Packet::new(ethernet.payload());

    if let Some(header) = header {
        // Extract the source and destination ip address
        let ip_sorg = IpAddr::V6(header.get_source());
        let ip_dest = IpAddr::V6(header.get_destination());

        // Save them in the Packet Info structure
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg{
            new_packet_info.set_not_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
            new_packet_info.set_not_printed();
        }

        // Save them in the Packet Info structure
        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        handle_transport_protocol(
            ip_sorg,
            ip_dest,
            header.get_next_header(),
            header.payload(),
            new_packet_info,
            filter,
        );
    } else {
        println!("Malformed IPv6 Packet");
    }
}

fn handle_arp_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    let header = ArpPacket::new(ethernet.payload());

    if let Some(header) = header {
        let ip_sorg = IpAddr::V4(header.get_sender_proto_addr());
        let ip_dest = IpAddr::V4(header.get_target_proto_addr());

        //NON STAMPO IL PACCHETTO SOLO SE:
        //IL FILTRO SUL PROTOCOLLO ESISTE ED E' DIVERSO DA ARP
        //IL FILTRO SULL'INDIRIZZO ESISTE ED E' DIVERSO DA QUELLO CORRENTE
        if filter.protocol != Protocol::None && filter.protocol != Protocol::Arp{
            new_packet_info.set_not_printed();
        }
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg{
            new_packet_info.set_not_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest{
            new_packet_info.set_not_printed();
        }
        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Arp);

        if new_packet_info.printed {
            println!(
                "ARP packet: {}({}) > {}({}); operation: {:?}",
                ethernet.get_source(),
                header.get_sender_proto_addr(),
                ethernet.get_destination(),
                header.get_target_proto_addr(),
                header.get_operation(),
            );
        }
    } else {
        println!("Malformed ARP Packet");
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    PacketInfo::set_dim(new_packet_info, ethernet.packet().len());
    let dim_header = ethernet.packet().len() - ethernet.payload().len();
    //println!("\n DIM_tot = {}, Dim_header = {}, protocol filtrato = {}", ethernet.packet().len(), dim_header, filter.protocol);

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, new_packet_info, filter),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, new_packet_info, filter),
        EtherTypes::Arp => handle_arp_packet(ethernet, new_packet_info, filter),
        _ => {
            if filter.protocol == Protocol::None {
                println!(
                    "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                    ethernet.get_source(),
                    ethernet.get_destination(),
                    ethernet.get_ethertype(),
                    ethernet.packet().len()
                )
            }
        }
    }
}

/*
static WELL_KNOWN_PORTS_UDP: HashMap<usize, ApplicationProtocol> = HashMap::from(
    [ (53, ApplicationProtocol::Dns), (68, ApplicationProtocol::Dhcp)]
);

static WELL_KNOWN_PORTS_TCP: HashMap<usize, ApplicationProtocol> = HashMap::from(
  [
      (22, ApplicationProtocol::Ssh), (23, ApplicationProtocol::Telnet),
      (80, ApplicationProtocol::Http), (88, ApplicationProtocol::Kerberos),
      (110, ApplicationProtocol::Pop), (143, ApplicationProtocol::Imap),
      (443, ApplicationProtocol::Https), (465, ApplicationProtocol::Smtp),
      (995, ApplicationProtocol::Pop3)
  ]
);

pub enum ApplicationProtocol{
    Ssh,
    Telnet,
    Dhcp, //c'è il parser
    Http, //c'è il parser
    Kerberos,
    Pop,
    Imap,
    Https,
    Smtp,
    Pop3
}

 */


/*
*  DATA STRUCTURES
*/

/* -------- Protocol enum ---------*/
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    Ethernet,
    Arp,
    IpV4,
    IpV6,
    Udp,
    Tcp,
    IcmpV4,
    IcmpV6,
    Dns,
    Tls,
    None,
}

impl FromStr for Protocol {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "Ethernet" => Ok(Protocol::Ethernet),
            "Arp" => Ok(Protocol::Arp),
            "IpV4" => Ok(Protocol::IpV4),
            "IpV6" => Ok(Protocol::IpV6),
            "Udp" => Ok(Protocol::Udp),
            "Tcp" => Ok(Protocol::Tcp),
            "IcmpV4" => Ok(Protocol::IcmpV4),
            "IcmpV6" => Ok(Protocol::IcmpV6),
            "Dns" => Ok(Protocol::Dns),
            "Tls" => Ok(Protocol::Tls),
            "None" => Ok(Protocol::None),
            _ => Err(()),
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            Protocol::Ethernet => write!(f, "Ethernet"),
            Protocol::Arp => write!(f, "ARP"),
            Protocol::IpV4 => write!(f, "IP version 4"),
            Protocol::IpV6 => write!(f, "IP version 6"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::IcmpV4 => write!(f, "ICMP version 4"),
            Protocol::IcmpV6 => write!(f, "ICMP version 6"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Tls => write!(f, "TLS"),
            Protocol::None => write!(f, "None"),
        }
    }
}

/* -------- Packet info structure ---------*/
#[derive(Debug)]
struct PacketInfo {
    ip_sorg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_sorg: u16,
    prt_dest: u16,
    protocol: Protocol,
    dim: usize,
    //TODO: ok dimensione?
    arrival_time: Option<Duration>,
    printed: bool,
}

impl PacketInfo {
    pub fn new() -> Self {
        return PacketInfo {
            ip_sorg: None,
            ip_dest: None,
            prt_sorg: 0,
            prt_dest: 0,
            protocol: Protocol::None,
            dim: 0,
            arrival_time: None,
            printed: true,
        };
    }

    pub fn set_dim(&mut self, dim: usize) {
        self.dim = dim
    }

    pub fn set_time(&mut self, time: Duration) {
        self.arrival_time = Some(time)
    }

    pub fn set_ip_sorgente(&mut self, ip_sorg: IpAddr) {
        self.ip_sorg = Some(ip_sorg);
    }

    pub fn set_ip_destinazione(&mut self, ip_dest: IpAddr) {
        self.ip_dest = Some(ip_dest);
    }

    pub fn set_porta_sorgente(&mut self, porta_sorg: u16) {
        self.prt_sorg = porta_sorg;
    }

    pub fn set_porta_destinazione(&mut self, porta_dest: u16) {
        self.prt_dest = porta_dest;
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol
    }

    pub fn set_not_printed(&mut self) {
        self.printed = false;
    }
}

/* -------- Conversation Stats struct ---------*/
#[derive(Debug)]
struct ConversationStats {
    tot_bytes: usize,
    starting_time: Option<Duration>,
    ending_time: Option<Duration>,
}

impl ConversationStats {
    pub fn new() -> Self {
        return ConversationStats {
            tot_bytes: 0,
            starting_time: None,
            ending_time: None,
        };
    }

    pub fn with_details(tot_bytes: usize, start: Duration, end: Duration) -> Self {
        return ConversationStats {
            tot_bytes,
            starting_time: Some(start),
            ending_time: Some(end),
        };
    }
    pub fn set_starting_time(&mut self, start: Duration) {
        self.starting_time = Some(start);
    }

    pub fn set_ending_time(&mut self, end: Duration) {
        self.ending_time = Some(end);
    }
}

/* -------- Conversation Key struct ---------*/
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ConversationKey {
    ip_srg: IpAddr,
    ip_dest: IpAddr,
    prt_srg: u16,
    prt_dest: u16,
    protocol: Protocol,
}

impl ConversationKey {
    pub fn new_key(ip_srg: IpAddr,
                   ip_dest: IpAddr,
                   prt_srg: u16,
                   prt_dest: u16,
                   protocol: Protocol)
                   -> Self {
        return ConversationKey {
            ip_srg,
            ip_dest,
            prt_srg,
            prt_dest,
            protocol,
        };
    }
}

pub enum FilterEnum {
    IpSorg,
    IpDest,
    PortSorg,
    PortDest,
    IsoOsiProtocol,
}

#[derive(Debug)]
pub struct Filter {
    ip_srg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_srg: Option<u16>,
    prt_dest: Option<u16>,
    protocol: Protocol,
}

impl Filter {
    pub fn new() -> Self {
        return Filter {
            ip_srg: None,
            ip_dest: None,
            prt_srg: None,
            prt_dest: None,
            protocol: Protocol::None,
        };
    }
    pub fn set_ip_srg(&mut self, ip: IpAddr) {
        self.ip_srg = Some(ip);
    }
    pub fn set_ip_dest(&mut self, ip: IpAddr) {
        self.ip_dest = Some(ip);
    }
    pub fn set_prt_srg(&mut self, prt: u16) {
        self.prt_srg = Some(prt);
    }
    pub fn set_prt_dest(&mut self, prt: u16) {
        self.prt_dest = Some(prt);
    }
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }

    pub fn populate(&mut self, filter_enum: FilterEnum) {
        match filter_enum {
            FilterEnum::IpSorg => {
                let mut ip = String::new();
                print!("> [Source Ip Address]: ");
                io::stdout().flush().expect("Error");
                loop {
                    io::stdin().read_line(&mut ip).expect("Error reading the source IP address");
                    ip = ip.trim().to_string();

                    if ip == "_".to_string() {
                        self.ip_srg = None;
                        break;
                    }
                    match ip.parse::<IpAddr>() {
                        Ok(address) => {
                            self.ip_srg = Some(address);
                        }
                        Err(_) => {
                            println!("> Please, insert a correct IP address or _!");
                        }
                    }
                }
            }
            FilterEnum::IpDest => {
                let mut ip = String::new();
                print!("> [Dest Ip Address]: ");
                io::stdout().flush().expect("Error");
                loop {
                    io::stdin().read_line(&mut ip).expect("Error reading the source IP address");
                    ip = ip.trim().to_string();

                    if ip == "_".to_string() {
                        self.ip_dest = None;
                        break;
                    }
                    match ip.parse::<IpAddr>() {
                        Ok(address) => {
                            self.ip_dest = Some(address);
                        }
                        Err(_) => {
                            println!("> Please, insert a correct port number!");
                        }
                    }
                }
            }
            FilterEnum::PortSorg => {
                let mut prt = String::new();
                print!("> [Source Port]: ");
                io::stdout().flush().expect("Error");

                loop {
                    io::stdin().read_line(&mut prt).expect("Error reading the source port");
                    prt = prt.trim().to_string();

                    if prt == "_".to_string() {
                        self.prt_srg = None;
                        break;
                    }
                    match prt.parse::<u16>() {
                        Ok(port) => {
                            self.prt_srg = Some(port);
                        }
                        Err(_) => {
                            println!(">Please, insert a correct port number!");
                        }
                    }
                }
            }
            FilterEnum::PortDest => {
                let mut prt = String::new();
                print!("> [Destination Port]:");
                io::stdout().flush().expect("Error");
                loop {
                    io::stdin().read_line(&mut prt).expect("Error reading the destination port");
                    prt = prt.trim().to_string();

                    if prt == "_".to_string() {
                        self.prt_dest = None;
                        break;
                    }
                    match prt.parse::<u16>() {
                        Ok(port) => {
                            self.prt_dest = Some(port);
                        }
                        Err(_) => {
                            println!("Please, insert a correct port number!");
                        }
                    }
                }
            }
            FilterEnum::IsoOsiProtocol => {
                let mut prot = String::new();
                print!("> [Protocol]: ");
                io::stdout().flush().expect("Error");
                loop {
                    io::stdin().read_line(&mut prot).expect("Error reading the source IP address");
                    prot = prot.trim().to_string();

                    if prot == "_".to_string() {
                        self.protocol = Protocol::None;
                        break;
                    }
                    match prot.parse::<Protocol>() {
                        Ok(protocol) => {
                            self.protocol = protocol;
                        }
                        Err(_) => {
                            println!("> Please, insert a correct protocol name!");
                        }
                    }
                }
            }
        }
    }
}


fn main() {
    let mut convs_summaries: HashMap<ConversationKey, ConversationStats> = HashMap::new();

    /*
    *  INITIALIZATION
    *
    */


    let (interface, time_interval, filename, filter) = fast_init_sniffing();
    //let (interface, time_interval, filename, filter) = init_sniffing();


    /*
    // Create a channel to receive on
    let conf = pnet_datalink::Config {
        write_buffer_size: 32768,
        read_buffer_size: 32768,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet_datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
    };


     */
    let (_, mut rx) = match datalink::channel(&interface, pnet_datalink::Config::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };
    // record the initial time
    let time_0 = SystemTime::now();
    println!("............................");
    println!("... sniffing the network...");
    println!("............................");

    /*
    *  SNIFFING
    *
    */

    //l'header ethernet è formato da almeno 14 pezzi -> minimum packet size ritorna 14
    //println!("min {}", MutableEthernetPacket::minimum_packet_size());

    let mut i = 0;
    loop {
        let mut buf: [u8; 1600] = [0u8; 1600]; //il frame ethernet è di 1518 byte -> sovradimensionato a 1600
        let mut new_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        match rx.next() {
            Ok(packet) => {
                // Packet arrival time
                let intial_time = SystemTime::now().duration_since(time_0).expect("TIME ERROR");
                // Create a data structure to host the information got from the packet
                let mut new_packet_info = PacketInfo::new();
                // Set arrival packet time
                PacketInfo::set_time(&mut new_packet_info, intial_time);

                // Handle particular cases
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
                            handle_ethernet_frame(&new_ethernet_frame.to_immutable(), &mut new_packet_info, &filter);
                            continue;
                        } else if version == 6 {
                            println!("CASO PARTICOLARE 2");
                            new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            new_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            new_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&new_ethernet_frame.to_immutable(), &mut new_packet_info, &filter);
                            continue;
                        }
                    }
                }

                //println!("DIM DEL PACCHETTO ARRIVATO = {}", packet.len());
                // Parse the ethernet frame
                handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &mut new_packet_info, &filter);

                if true // new_packet_info.printed
                {
                    // Create the key of the packet considering (ip_sorg, ip_dest, port_sorg, port_dest, prot)
                    let key = ConversationKey::new_key(new_packet_info.ip_sorg.unwrap(),
                                                       new_packet_info.ip_dest.unwrap(),
                                                       new_packet_info.prt_sorg,
                                                       new_packet_info.prt_dest,
                                                       new_packet_info.protocol);
                    // If the packet belongs to a conversation already present in the map, update the stats, otherwise add a new record
                    convs_summaries.entry(key)
                        .and_modify(|entry| {
                            entry.tot_bytes += new_packet_info.dim;
                            entry.ending_time = new_packet_info.arrival_time;
                        })
                        .or_insert(ConversationStats::with_details(new_packet_info.dim,
                                                                   new_packet_info.arrival_time.unwrap(),
                                                                   new_packet_info.arrival_time.unwrap()));
                }
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
        if i == 60 {
            break;
        }
        i += 1;
    }

    /*
    *  PRINT
    *
    */

    let mut file = open_file(filename).expect("ERRORE FILE");
    write_summaries(&mut file, convs_summaries);
}


/*
use pcap::{Device,Capture};

fn main() {
    let mut i = 0;
    let list = Device::list().unwrap();
    let mut main_device = Device::lookup().unwrap().unwrap();
    for device in list{
        println!("{:?} {:?}", device.name, device.desc);
        if i == 3{
            println!("*****chosen");
            main_device = device;
        }
        i+=1;
    }
    println!();
    println!("{:?}", main_device);
    let mut cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .open().unwrap();

    println!("stampa");
    while let Ok(packet) = cap.next_packet() {
        println!("len{} -> len{}", packet.len(), packet.header.len);
    }
}
*/