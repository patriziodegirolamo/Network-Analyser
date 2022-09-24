extern crate pnet;

use enum_iterator::Sequence;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use pnet::packet::arp::{ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

//use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration};
use prettytable::{Cell, Row, Table};

use std::fs::{File};
use std::str::FromStr;
use pcap::Error;

/* -------- Protocol enum ---------*/
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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
pub struct PacketInfo {
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

    /*
    Getter methods
     */
    pub fn get_dim(&self) -> usize {
        return self.dim;
    }

    pub fn get_time(&self) -> Option<Duration> {
        return self.arrival_time;
    }

    pub fn get_ip_sorgente(&self) -> Option<IpAddr> { return self.ip_sorg }

    pub fn get_ip_destinazione(&self) -> Option<IpAddr> { return self.ip_dest }

    pub fn get_porta_sorgente(&self) -> u16 {
        self.prt_sorg
    }

    pub fn get_porta_destinazione(&self) -> u16 {
        self.prt_dest
    }

    pub fn get_protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn get_printed(&self) -> bool {
        return self.printed;
    }


    /*
    Setter methods
     */
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
pub struct ConversationStats {
    tot_bytes: usize,
    starting_time: Option<Duration>,
    ending_time: Option<Duration>,
}

impl ConversationStats {

    pub fn new(tot_bytes: usize, start: Duration, end: Duration) -> Self {
        return ConversationStats {
            tot_bytes,
            starting_time: Some(start),
            ending_time: Some(end),
        };
    }

    pub fn get_starting_time(&self) -> Option<Duration> {return self.starting_time}
    pub fn get_ending_time(&self) -> Option<Duration> {return  self.ending_time}
    pub fn get_tot_bytes(&self) -> usize {return self.tot_bytes}

    pub fn set_starting_time(&mut self, start: Duration) {
        self.starting_time = Some(start);
    }

    pub fn set_ending_time(&mut self, end: Duration) {
        self.ending_time = Some(end);
    }

    pub fn set_tot_bytes(&mut self, to_add: usize) {
        self.tot_bytes += to_add;
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

    pub fn get_ip_srg(&self) -> IpAddr{ return self.ip_srg}
    pub fn get_ip_dest(&self) -> IpAddr{ return self.ip_dest}
    pub fn get_prt_srg(&self) -> u16{ return self.prt_srg}
    pub fn get_prt_dest(&self) -> u16{ return self.prt_dest}
    pub fn get_protocol(&self) -> Protocol{ return self.protocol}
}

#[derive(Sequence)]
pub enum FilteredProtocol {
    Dns = 0,
    Tls,
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
    Arp
}

impl Display for FilteredProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            FilteredProtocol::Dns => write!(f, "Dns"),
            FilteredProtocol::Tls => write!(f, "Tls"),
            FilteredProtocol::Tcp => write!(f, "Tcp"),
            FilteredProtocol::Udp => write!(f, "Udp"),
            FilteredProtocol::IcmpV4 => write!(f, "IcmpV4"),
            FilteredProtocol::IcmpV6 => write!(f, "IcmpV6"),
            FilteredProtocol::Arp => write!(f, "Arp"),
        }
    }
}

#[derive(Debug)]
pub struct Filter {
    ip_srg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_srg: Option<u16>,
    prt_dest: Option<u16>,
    protocol: Protocol,
}

impl Display for Filter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: mettere delle stampe migliori se è none l'option! (Non valore di default)
        let ip_def = IpAddr::V4(Ipv4Addr::new(1,1,1,1));
        let prt_def = 0;
        write!(f, "[ IP source: {}; IP dest: {}, Port source: {}, Port dest: {}, Protocol: {} ]",
               self.ip_srg.unwrap_or_else(|| ip_def),
               self.ip_dest.unwrap_or_else(|| ip_def),
               self.prt_srg.unwrap_or_else(|| prt_def),
               self.prt_dest.unwrap_or_else(|| prt_def),
               self.protocol)
    }
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
}

/*
*  PROTOCOLS HANDLE FUNCTIONS
*
*/

fn handle_dns_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    if dns_parser::Packet::parse(packet).is_ok() {
        PacketInfo::set_protocol(new_packet_info, Protocol::Dns);

        if filter.protocol != Protocol::None && filter.protocol != Protocol::Dns {
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
    };
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        // Extract the source and destination port
        let prt_srg = udp.get_source();
        let prt_dest = udp.get_destination();

        // Save them in the PacketInfo structure

        //se esiste il filtro ed è diverso dalla porta sorgente
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg {
            new_packet_info.set_not_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest {
            new_packet_info.set_not_printed();
        }

        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Udp);
        if prt_srg == 53 || prt_dest == 53 {
            handle_dns_packet(udp.payload(), new_packet_info, filter);
        } else if new_packet_info.printed {
            if filter.protocol == Protocol::None || filter.protocol == Protocol::Udp {
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
        if filter.protocol != Protocol::IcmpV4 || filter.protocol != Protocol::IcmpV4 {
            new_packet_info.set_not_printed();
        }
        if new_packet_info.printed {
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
        } else {}
    } else {
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmpv6_packet = Icmpv6Packet::new(packet);

    if let Some(icmpv6_packet) = icmpv6_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV6);
        if filter.protocol != Protocol::IcmpV6 || filter.protocol != Protocol::IcmpV6 {
            new_packet_info.set_not_printed();
        } else if new_packet_info.printed {
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
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg {
            new_packet_info.set_not_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest {
            new_packet_info.set_not_printed();
        }

        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Tcp);
        // Check if the protocol carried is TLS

        if prt_srg == 53 || prt_dest == 53 {
            handle_dns_packet(tcp.payload(), new_packet_info, filter);
        } else if handle_tls_packet(tcp.payload(), new_packet_info, filter) {} else if new_packet_info.printed {
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
                _ => { new_packet_info.set_not_printed() }
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
                _ => { new_packet_info.set_not_printed(); }
            }
            handle_tcp_packet(source, destination, packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Icmp => {
            //se il protocollo non è icmp -> va filtrato
            if filter.protocol != Protocol::IcmpV4 {
                new_packet_info.set_not_printed();
            }
            handle_icmp_packet(source, destination, packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            //se il protocollo non è icmp -> va filtrato
            if filter.protocol != Protocol::IcmpV6 {
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

        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
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
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
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
        if filter.protocol != Protocol::None && filter.protocol != Protocol::Arp {
            new_packet_info.set_not_printed();
        }
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
            new_packet_info.set_not_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
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

pub fn handle_ethernet_frame(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    PacketInfo::set_dim(new_packet_info, ethernet.packet().len());
    //let dim_header = ethernet.packet().len() - ethernet.payload().len();
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
