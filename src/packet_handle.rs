extern crate pnet;

use enum_iterator::Sequence;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
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

//use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration};
use prettytable::{Cell, Row, Table};

use std::fs::{File};
use std::str::FromStr;
use pcap::Error;
use pnet_datalink::{MacAddr, NetworkInterface};

/* -------- Protocol enum ---------*/
#[derive(Sequence, Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    Ethernet = 0,
    Arp,
    IpV4,
    IpV6,
    Udp,
    Tcp,
    IcmpV4,
    IcmpV6,
    Dns,
    Tls,
    None
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
#[derive(Debug, Clone)]
pub struct PacketInfo {

    ip_sorg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_sorg: u16,
    prt_dest: u16,
    protocol: Protocol,
    dim: usize,
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
            printed: false,
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

    pub fn set_printed(&mut self) {
        self.printed = true;
    }
}

/* -------- Conversation Stats struct ---------*/
#[derive(Debug, Copy, Clone)]
pub struct ConversationStats {
    tot_bytes: usize,
    starting_time: Option<Duration>,
    ending_time: Option<Duration>,
    tot_packets: usize,
}

impl ConversationStats {

    pub fn new(tot_bytes: usize, start: Duration, end: Duration, tot_packets: usize) -> Self {
        return ConversationStats {
            tot_bytes,
            starting_time: Some(start),
            ending_time: Some(end),
            tot_packets,
            //TODO: add number of packets exchanged
            //TODO: add Application Information
        };
    }

    pub fn get_starting_time(&self) -> Option<Duration> {return self.starting_time}
    pub fn get_ending_time(&self) -> Option<Duration> {return  self.ending_time}
    pub fn get_tot_bytes(&self) -> usize {return self.tot_bytes}
    pub fn get_tot_packets(&self) -> usize {return self.tot_packets}

    pub fn set_starting_time(&mut self, start: Duration) {
        self.starting_time = Some(start);
    }

    pub fn set_ending_time(&mut self, end: Duration) {
        self.ending_time = Some(end);
    }

    pub fn set_tot_bytes(&mut self, to_add: usize) {
        self.tot_bytes += to_add;
    }

    pub fn set_tot_packets(&mut self, to_add: usize) {
        self.tot_packets += to_add;
    }
}

/* -------- Conversation Key struct ---------*/
#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone)]
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

#[derive(Debug, Clone, Copy)]
pub struct Filter {
    ip_srg: Option<IpAddr>,
    ip_dest: Option<IpAddr>,
    prt_srg: Option<u16>,
    prt_dest: Option<u16>,
    protocol: Protocol,
}

impl Display for Filter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {

        write!(f, "[ IP source: {}; IP dest: {}, Port source: {}, Port dest: {}, Protocol: {} ]",
               match self.ip_srg {
                   Some(ip) => ip.to_string(),
                   _ => "Any".to_string()
                },
               match self.ip_dest {
                    Some(ip) => ip.to_string(),
                    _ => "Any".to_string()
                },
               match self.prt_srg {
                   Some(p) => p.to_string(),
                   _ => "Any".to_string()
                },
               match self.prt_dest {
                   Some(p) => p.to_string(),
                   _ => "Any".to_string()
               },
               match self.protocol {
                   Protocol::None => "Any".to_string(),
                   p => p.to_string()
               })
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

    pub fn get_ip_srg(&self) -> Option<IpAddr> { return self.ip_srg}
    pub fn get_ip_dest(&self) -> Option<IpAddr> { return self.ip_dest}
    pub fn get_prt_srg(&self) -> Option<u16> { return self.prt_srg}
    pub fn get_prt_dest(&self) -> Option<u16> { return self.prt_dest}
    pub fn get_protocol(&self) -> Protocol{ return self.protocol}
}

/*
*  PROTOCOLS HANDLE FUNCTIONS
*
*/

fn handle_dns_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    match dns_parser::Packet::parse(packet) {
        Ok(dns_packet) => {
            PacketInfo::set_protocol(new_packet_info, Protocol::Dns);
            if filter.protocol == Protocol::Dns {
                new_packet_info.set_printed();
            }

            let questions = dns_packet.questions.iter().map(|q| { q.qname.to_string() }).collect::<Vec<String>>();
            //TODO: inserire le questions nel file di report
            //println!("DNS questions: {:?}", questions);
        }
        Err(_) => {}
    }
}

fn handle_tls_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {

    match  tls_parser::parse_tls_plaintext(packet) {
        Ok(tls_packet) => {
            PacketInfo::set_protocol(new_packet_info, Protocol::Tls);
            //println!("TLS plaintext {:?}", tls_packet.1);
            if filter.protocol == Protocol::Tls {
                new_packet_info.set_printed();
            }
        },
        Err(_) => {}
    }

    match  tls_parser::parse_tls_encrypted(packet) {
        Ok(tls_packet) => {
            PacketInfo::set_protocol(new_packet_info, Protocol::Tls);
            //println!("TLS encrypted {:?}", tls_packet.1);
            if filter.protocol == Protocol::Tls {
                new_packet_info.set_printed();
            }
        },
        Err(_) => {}
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        // Extract the source and destination port
        let prt_srg = udp.get_source();
        let prt_dest = udp.get_destination();

        // Save them in the PacketInfo structure

        if filter.protocol == Protocol::Udp {
            new_packet_info.set_printed();
        }

        //se esiste il filtro ed è diverso dalla porta sorgente
        /*
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg {
            new_packet_info.set_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest {
            new_packet_info.set_printed();
        }

         */

        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Udp);

        handle_dns_packet(udp.payload(), new_packet_info, filter);
    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmp_packet = IcmpPacket::new(packet);

    if let Some(icmp_packet) = icmp_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV4);
        if filter.protocol == Protocol::IcmpV4 {
            new_packet_info.set_printed();
        }
        /*
        if new_packet_info.printed {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                }
                _ => {

                },
            }
        } else {}

         */
    } else {
        println!("Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmpv6_packet = Icmpv6Packet::new(packet);

    if let Some(_) = icmpv6_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV6);
        if filter.protocol == Protocol::IcmpV6 {
            new_packet_info.set_printed();
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

        if filter.protocol == Protocol::Tcp {
            new_packet_info.set_printed();
        }

        //se esiste il filtro ed è diverso dalla porta sorgente
        /*
        if filter.prt_srg.is_some() && filter.prt_srg.unwrap() != prt_srg {
            new_packet_info.set_printed();
        }
        if filter.prt_dest.is_some() && filter.prt_dest.unwrap() != prt_dest {
            new_packet_info.set_printed();
        }

         */

        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Tcp);
        // Check if the protocol carried is TLS or DNS
        handle_tls_packet(tcp.payload(), new_packet_info, filter);
        handle_dns_packet(tcp.payload(), new_packet_info, filter);
    } else {
        println!("Malformed TCP Packet");
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr, protocol: IpNextHeaderProtocol, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            //se il protocollo è udp ma il filtro è diverso da udp, dns o none -> il pacchetto va filtrato
            /*match filter.protocol {
                Protocol::Udp => {}
                Protocol::Dns => {}
                Protocol::None => {}
                _ => { new_packet_info.set_printed() }
            }

             */
            handle_udp_packet(source, destination, packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Tcp => {
            //se il protocollo è tcp ma il filtro è diverso da tcp, tls, dns o none -> il pacchetto va filtrato
            /*
            match filter.protocol {
                Protocol::Tls => {}
                Protocol::Tcp => {}
                Protocol::Dns => {}
                Protocol::None => {}
                _ => { new_packet_info.set_printed(); }
            }
             */
            handle_tcp_packet(source, destination, packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Icmp => {
            //se il protocollo non è icmp -> va filtrato
            /*
            if filter.protocol != Protocol::IcmpV4 {
                new_packet_info.set_printed();
            }

             */
            handle_icmp_packet(source, destination, packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            //se il protocollo non è icmp -> va filtrato
            /*
            if filter.protocol != Protocol::IcmpV6 {
                new_packet_info.set_printed();
            }

             */
            handle_icmpv6_packet(source, destination, packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Pipe => {
            //IP over IP
            //TODO: handle filter PIPE
            println!("PIPE");
        }
        IpNextHeaderProtocols::Igmp => {
            //TODO: handle filter IGMP
            println!("IGMP");
        }
        _ => {
            println!("Unknown transport level protocol {}!", protocol);
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

        // If there is a filter on the protocol and it is IPv4
        if filter.protocol == Protocol::IpV4 {
            new_packet_info.set_printed();
        }

        /*
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
            new_packet_info.set_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
            new_packet_info.set_printed();
        }
        */

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

        // If there is a filter on the protocol and it is IPv6
        if filter.protocol == Protocol::IpV6 {
            new_packet_info.set_printed();
        }

        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
            new_packet_info.set_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
            new_packet_info.set_printed();
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

        // If there is a filter on the protocol and it is IPv4
        if filter.protocol == Protocol::Arp {
            new_packet_info.set_printed();
        }

        /*
        if filter.protocol != Protocol::None && filter.protocol != Protocol::Arp {
            new_packet_info.set_printed();
        }
        if filter.ip_srg.is_some() && filter.ip_srg.unwrap() != ip_sorg {
            new_packet_info.set_printed();
        }
        if filter.ip_dest.is_some() && filter.ip_dest.unwrap() != ip_dest {
            new_packet_info.set_printed();
        }
         */
        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Arp);

    } else {
        println!("Malformed ARP Packet");
    }
}

pub fn handle_ethernet_frame(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    PacketInfo::set_dim(new_packet_info, ethernet.packet().len());
    //let dim_header = ethernet.packet().len() - ethernet.payload().len();
    //println!("\n DIM_tot = {}, Dim_header = {}, protocol filtrato = {}", ethernet.packet().len(), dim_header, filter.protocol);

    // If there is no filter on the protocol, packet is set printed
    if filter.protocol == Protocol::None {
        new_packet_info.set_printed();
    }

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, new_packet_info, filter),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, new_packet_info, filter),
        EtherTypes::Arp => handle_arp_packet(ethernet, new_packet_info, filter),
        _ => {
            println!("unknown lvl 3 protocol");
        }
    }
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
                //println!("CASO PARTICOLARE 1");
                new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                new_ethernet_frame.set_payload(&packet[payload_offset..]);
                handle_ethernet_frame(&new_ethernet_frame.to_immutable(), new_packet_info, &filter);
                return true;
            } else if version == 6 {
                //println!("CASO PARTICOLARE 2");
                new_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                new_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                new_ethernet_frame.set_payload(&packet[payload_offset..]);
                handle_ethernet_frame(&new_ethernet_frame.to_immutable(), new_packet_info, &filter);
                return true;
            }
        }
    }
    return false;
}
