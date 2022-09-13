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
//use std::process;

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        // Extract the source and destination port
        let prt_srg = udp.get_source();
        let prt_dest = udp.get_destination();
        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info,prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);

        if prt_srg =={

        }
        PacketInfo::set_protocol(new_packet_info,Protocol::Udp);

        println!(
            "UDP Packet: {}:{} > {}:{}; length: {}",
            source,
            prt_srg,
            destination,
            prt_dest,
            udp.get_length()
        );
    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo) {
    let icmp_packet = IcmpPacket::new(packet);

    if let Some(icmp_packet) = icmp_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info,Protocol::IcmpV4);
        // TODO: tipo di icmp???
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
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo) {
    let icmpv6_packet = Icmpv6Packet::new(packet);

    if let Some(icmpv6_packet) = icmpv6_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info,Protocol::IcmpV6);
        println!(
            "ICMPv6 packet {} -> {} (type={:?})",
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("Malformed ICMPv6 Packet");
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo) {
    let tcp = TcpPacket::new(packet);


    if let Some(tcp) = tcp {
        // Extract the source and destination ports
        let prt_srg = tcp.get_source();
        let prt_dest = tcp.get_destination();
        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info,prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info,Protocol::Tcp);

        println!(
            "TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            prt_srg,
            destination,
            prt_dest,
            packet.len()
        );
    } else {
        println!("Malformed TCP Packet");
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr, protocol: IpNextHeaderProtocol, packet: &[u8], new_packet_info: &mut PacketInfo) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(source, destination, packet, new_packet_info)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet( source, destination, packet, new_packet_info)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(source, destination, packet, new_packet_info)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(source, destination, packet, new_packet_info)
        }
        _ => println!(
            "Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo) {
    let header = Ipv4Packet::new(ethernet.payload());

    if let Some(header) = header {
        // Extract the source and destination ip address
        let ip_sorg = IpAddr::V4(header.get_source());
        let ip_dest = IpAddr::V4(header.get_destination());
        // Save them in the Packet Info structure
        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        handle_transport_protocol(
            ip_sorg,
            ip_dest,
            header.get_next_level_protocol(),
            header.payload(),
            new_packet_info
        );
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ipv6_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo) {
    let header = Ipv6Packet::new(ethernet.payload());

    if let Some(header) = header {
        // Extract the source and destination ip address
        let ip_sorg = IpAddr::V6(header.get_source());
        let ip_dest = IpAddr::V6(header.get_destination());
        // Save them in the Packet Info structure
        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        handle_transport_protocol(
            ip_sorg,
            ip_dest,
            header.get_next_header(),
            header.payload(),
            new_packet_info
        );
    } else {
        println!("Malformed IPv6 Packet");
    }
}

fn handle_arp_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo) {
    let header = ArpPacket::new(ethernet.payload());

    if let Some(header) = header {
        PacketInfo::set_ip_sorgente(new_packet_info, IpAddr::V4( header.get_sender_proto_addr()));
        PacketInfo::set_ip_destinazione(new_packet_info, IpAddr::V4(header.get_target_proto_addr()));
        PacketInfo::set_protocol(new_packet_info, Protocol::Arp);

        println!(
            "ARP packet: {}({}) > {}({}); operation: {:?}",
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation(),
        );
    } else {
        println!("Malformed ARP Packet");
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo) {
    PacketInfo::set_dim(new_packet_info, ethernet.packet().len());
    new_packet_info.dim = ethernet.packet().len();
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, new_packet_info),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, new_packet_info),
        EtherTypes::Arp => handle_arp_packet(ethernet, new_packet_info),
        _ => println!(
            "Unknown packet: {} > {}; ethertype: {:?} length: {}",
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

fn print_devices(){
    let interfaces = datalink::interfaces();
    for (i,inter) in interfaces.into_iter().enumerate() {
        println!("{}:   {:?} {:?}", i, inter.name, inter.description);
    }
}

fn select_device_by_name(name: String) -> NetworkInterface {
    let interfaces = datalink::interfaces();
    let chosen_interface = interfaces
        .into_iter()
        .filter(|inter| inter.name == name)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", name));
    println!("selected device: {:?}", chosen_interface.name);
    return chosen_interface;
}

fn find_my_device_name(index: usize) -> String {
    return datalink::interfaces().get(index).unwrap().clone().name;
}

static WELL_KNOWN_PORTS: HashMap<(usize, Protocol), ApplicationProtocol> = HashMap::new();

pub enum ApplicationProtocol{
    Ssh,
    Telnet,
    Dns,
    Dhcp,
    Http,
    Kerberos,
    Pop,
    Imap,
    Snmp,
    Https,
    Smtp,
    Pop3
}

//22/tcp	SSH - Secure login, file transfer (scp, sftp) e port forwarding
23/tcp	Telnet insecure text communications
25/tcp	SMTP - Simple Mail Transfer Protocol (E-mail)
53/udp	DNS - Domain Name System
67/udp	BOOTP Bootstrap Protocol (Server) e DHCP Dynamic Host Configuration Protocol (Server)
68/udp	BOOTP Bootstrap Protocol (Client) e DHCP Dynamic Host Configuration Protocol (Client)
69/udp	TFTP Trivial File Transfer Protocol
80/tcp	HTTP HyperText Transfer Protocol (WWW)
88/tcp	Kerberos Authenticating agent
110/tcp	POP Post Office Protocol (E-mail)
143/tcp	IMAP4 Internet Message Access Protocol (E-mail)
161/udp	SNMP Simple Network Management Protocol (Agent)
162/udp	SNMP Simple Network Management Protocol (Manager)
443/tcp	HTTPS usato per il trasferimento sicuro di pagine web
465/tcp	SMTP - Simple Mail Transfer Protocol (E-mail) su SSL
554/udp	RTSP
563/tcp	NNTP Network News Transfer Protocol (newsgroup Usenet) su SSL
587/tcp	e-mail message submission (SMTP)
993/tcp	IMAP4 Internet Message Access Protocol (E-mail) su SSL
995/tcp	POP3 Post Office Protocol (E-mail) su SSL
    None
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Protocol{
    Ethernet,
    Arp,
    IpV4,
    IpV6,
    Udp,
    Tcp,
    IcmpV4,
    IcmpV6,
    None
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
            Protocol::None => write!(f, "None"),
        }
    }
}

#[derive(Debug)]
struct PacketInfo{
    ip_sorg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_sorg: u16,
    prt_dest: u16,
    protocol: Protocol,
    dim: usize, //TODO: ok dimensione?
    arrival_time: Option<Duration>
}

impl PacketInfo {
    pub fn new() -> Self{
        return PacketInfo{
            ip_sorg: None,
            ip_dest: None,
            prt_sorg: 0,
            prt_dest: 0,
            protocol: Protocol::None,
            dim: 0,
            arrival_time: None
        }
    }

    pub fn set_dim(&mut self, dim: usize){
        self.dim = dim
    }

    pub fn set_time(&mut self, time: Duration){
        self.arrival_time = Some(time)
    }

    pub fn set_ip_sorgente(&mut self, ip_sorg: IpAddr){
        self.ip_sorg = Some(ip_sorg);
    }

    pub fn set_ip_destinazione(&mut self, ip_dest: IpAddr){
        self.ip_dest = Some(ip_dest);
    }

    pub fn set_porta_sorgente(&mut self, porta_sorg: u16){
        self.prt_sorg = porta_sorg;
    }

    pub fn set_porta_destinazione(&mut self, porta_dest: u16){
        self.prt_dest = porta_dest;
    }

    pub fn set_protocol(&mut self, protocol: Protocol){
        self.protocol = protocol
    }

}

#[derive(Debug)]
struct ConversationSummary {
    tot_bytes: usize,
    starting_time: Option<Duration>,
    ending_time: Option<Duration>
}

impl ConversationSummary {
    pub fn new() -> Self{
        return ConversationSummary{
            tot_bytes: 0,
            starting_time: None,
            ending_time: None
        }
    }

    pub fn with_details(tot_bytes: usize, start: Duration, end: Duration) -> Self{
        return ConversationSummary{
            tot_bytes,
            starting_time: Some(start),
            ending_time: Some(end)
        }
    }
    pub fn set_starting_time(&mut self, start: Duration){
        self.starting_time = Some(start);
    }

    pub fn set_ending_time(&mut self, end: Duration){
        self.ending_time = Some(end);
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ConversationKey{
    ip_srg: IpAddr,
    ip_dest: IpAddr,
    prt_srg: u16,
    prt_dest: u16,
    protocollo: Protocol
}

impl ConversationKey {
    pub fn new_key(ip_srg: IpAddr,
                   ip_dest: IpAddr,
                   prt_srg: u16,
                   prt_dest: u16,
                   protocollo: Protocol)
        -> Self{
        return ConversationKey{
            ip_srg, ip_dest, prt_srg, prt_dest, protocollo
        }
    }
}
fn main() {

    let mut info_packets : Vec<PacketInfo> = vec![];
    let mut convs_summaries: HashMap<ConversationKey, ConversationSummary> = HashMap::new();

    /*
    let key = ConversationKey::new_key(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpAddr::V4(Ipv4Addr::new(129, 0, 0, 1)), 15, 150, Protocol::Tcp);

    let mut conv = ConversationSummary::new();
    ConversationSummary::set_starting_time(&mut conv, SystemTime::now());
    ConversationSummary::set_ending_time(&mut conv, SystemTime::now());

    convs_summaries.insert(key, conv);
    println!("{:?} {:?}", convs_summaries.keys(), convs_summaries.values());
    */
    print_devices();

    println!("Seleziona l'indice corrispondente ad una delle seguenti interfacce di rete:");
    let mut my_index_str = String::new();

    io::stdin().read_line(&mut my_index_str).expect("errore in lettura");

    //TODO: controlla che index sia < di num interfacce
    //TODO: gestire con ciclo invece che con expect
    let my_index = my_index_str.trim().parse::<usize>().expect("errore, non hai inserito un numero valido");

    //non servirà con la console
    let dev_name = find_my_device_name(my_index);
    print!("Ok, hai selezionato {:?}", dev_name);

    let interface = select_device_by_name(dev_name);

    // Create a channel to receive on
    //TODO: in riga 167 del file lib.rs di pnet_datalink, la configurazione di default per creare un canale è impostata a mod promiscua
    let (_, mut rx) = match datalink::channel(&interface, pnet_datalink::Config::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    println!("... sniffing the network...");
    let time_0 = SystemTime::now();
    let mut i = 0;
    loop {
        let intial_time = SystemTime::now().duration_since(time_0).expect("TIME ERROR");

        //il frame ethernet è di 1518 byte -> sovradimensionato a 1600
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut new_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        match rx.next() {
            Ok(packet) => {

                let mut new_packet_info = PacketInfo::new();
                PacketInfo::set_time(&mut new_packet_info, intial_time);

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
                            handle_ethernet_frame(&new_ethernet_frame.to_immutable(), &mut new_packet_info);
                            continue;
                        } else if version == 6 {
                            println!("CASO PARTICOLARE 2");
                            new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            new_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            new_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&new_ethernet_frame.to_immutable(), &mut new_packet_info);
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &mut new_packet_info);

                let key = ConversationKey::new_key(new_packet_info.ip_sorg.unwrap(),
                                                       new_packet_info.ip_dest.unwrap(),
                                                        new_packet_info.prt_sorg,
                                                       new_packet_info.prt_dest,
                                                       new_packet_info.protocol);
                convs_summaries.entry(key).and_modify(|entry| {
                    entry.tot_bytes += new_packet_info.dim;
                    entry.ending_time = new_packet_info.arrival_time;
                }).or_insert(ConversationSummary::with_details(new_packet_info.dim,
                                                               new_packet_info.arrival_time.unwrap(),
                                                               new_packet_info.arrival_time.unwrap()));
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
        if i == 1000{
            break;
        }
        i+=1;
    }

    for (key, elem) in &convs_summaries{
        println!("{:?} {:?}", key, elem);
    }
}