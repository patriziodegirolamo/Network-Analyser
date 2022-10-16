extern crate pnet;

use enum_iterator::Sequence;
use std::fmt::{Display, Formatter};
use pnet::packet::arp::{ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{ IcmpPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use std::net::{IpAddr};
use std::time::{Duration};


use std::str::FromStr;
use pnet_datalink::{MacAddr, NetworkInterface};

/* -------- Protocol enum ---------*/
/// All possible Protocols that can be handled by the applications.
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
    Http,
    Https,
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
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Https => write!(f, "HTTPS"),
            Protocol::None => write!(f, "None"),
        }
    }
}

/* -------- Packet info structure ---------*/
#[derive(Debug, Clone)]
/// Object used to save relevant information of a sniffed packet.
/// - *ip_sorg*: Ip address of the source
/// - *ip_dest*: Ip address of the destination
/// - *prt_srg*: Source port
/// - *prt_dst*: Destination port
/// - *protocol*: Protocol carried by the packet
/// - *dim*: size in bytes of the packet
/// - *arrival_time*: when the packet arrived
/// - *printed*: whether the packet needs to be printed on the report or if it is filtered out by the user.
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
    /// Create a new PacketInfo object instance
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
    /// It returns the size in bytes of the packet
    pub fn get_dim(&self) -> usize {
        return self.dim;
    }
    /// It returns the arrival_time of the packet
    pub fn get_time(&self) -> Option<Duration> {
        return self.arrival_time;
    }
    /// It returns the source ip address
    pub fn get_ip_sorgente(&self) -> Option<IpAddr> { return self.ip_sorg }
    /// It returns the destination ip address
    pub fn get_ip_destinazione(&self) -> Option<IpAddr> { return self.ip_dest }
    /// It returns the source port
    pub fn get_porta_sorgente(&self) -> u16 {
        self.prt_sorg
    }
    /// It returns the destination port
    pub fn get_porta_destinazione(&self) -> u16 {
        self.prt_dest
    }
    /// It returns the protocol carried by the packet
    pub fn get_protocol(&self) -> Protocol {
        self.protocol
    }
    /// It returns whether the packets need to be printed or filtered out
    pub fn get_printed(&self) -> bool {
        return self.printed;
    }


    /*
    Setter methods
     */
    /// Set the size of the packet
    pub fn set_dim(&mut self, dim: usize) {
        self.dim = dim
    }
    /// Set the arrival time of the packet
    pub fn set_time(&mut self, time: Duration) {
        self.arrival_time = Some(time)
    }
    /// Set the source ip address
    pub fn set_ip_sorgente(&mut self, ip_sorg: IpAddr) {
        self.ip_sorg = Some(ip_sorg);
    }
    /// Set the destination ip address
    pub fn set_ip_destinazione(&mut self, ip_dest: IpAddr) {
        self.ip_dest = Some(ip_dest);
    }
    /// Set the source port
    pub fn set_porta_sorgente(&mut self, porta_sorg: u16) {
        self.prt_sorg = porta_sorg;
    }
    /// Set the destination port
    pub fn set_porta_destinazione(&mut self, porta_dest: u16) {
        self.prt_dest = porta_dest;
    }
    /// Set the protocol carried by the packet
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol
    }
    /// Set that the packet needs to be printed (true)
    pub fn set_printed(&mut self) {
        self.printed = true;
    }
}

/* -------- Conversation Stats struct ---------*/
#[derive(Debug, Copy, Clone)]
/// Object used to save relevant information on Conversations between (IP_source, PORT_source) and (IP_destination, PORT_destination) using a given Protocol.
///     - *tot_bytes*: total number of bytes exchanged
///     - *starting_time*: when the conversations started (considering as time 0 the time on which the sniffing began)
///     - *ending_time*: when the conversations ended (considering as time 0 the time on which the sniffing began)
///     - *tot_packets*: total number of packets exchanged
pub struct ConversationStats {
    tot_bytes: usize,
    starting_time: Option<Duration>,
    ending_time: Option<Duration>,
    tot_packets: usize,
}

impl ConversationStats {
    /// Create a new ConversationStats object instance and initialise its fields
    ///     - *tot_bytes*: total number of bytes exchanged
    ///     - *starting_time*: when the conversations started (considering as time 0 the time on which the sniffing began)
    ///     - *ending_time*: when the conversations ended (considering as time 0 the time on which the sniffing began)
    ///     - *tot_packets*: total number of packets exchanged

    pub fn new(tot_bytes: usize, start: Duration, end: Duration, tot_packets: usize) -> Self {
        return ConversationStats {
            tot_bytes,
            starting_time: Some(start),
            ending_time: Some(end),
            tot_packets,
        };
    }
    /// Get the starting time of the conversation (considering as time 0 the time on which the sniffing began)
    pub fn get_starting_time(&self) -> Option<Duration> {return self.starting_time}
    /// Get the ending time of the conversation (considering as time 0 the time on which the sniffing began)
    pub fn get_ending_time(&self) -> Option<Duration> {return  self.ending_time}
    /// Get the total number of bytes exchanged during the conversation
    pub fn get_tot_bytes(&self) -> usize {return self.tot_bytes}
    /// Get the total number of packets exchanged during the conversation
    pub fn get_tot_packets(&self) -> usize {return self.tot_packets}

    /// Set the ending time (considering as time 0 the time on which the sniffing began)
    pub fn set_ending_time(&mut self, end: Duration) {
        self.ending_time = Some(end);
    }
    /// Set the total bytes exchanged in the conversation
    pub fn set_tot_bytes(&mut self, to_add: usize) {
        self.tot_bytes += to_add;
    }
    /// Set the total number of packets exchanged
    pub fn set_tot_packets(&mut self, to_add: usize) {
        self.tot_packets += to_add;
    }
}

/* -------- Conversation Key struct ---------*/
#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone)]
/// Object containing the information that identify uniquely a Conversation.
///   - *ip_srg*: Ip address of the source of the conversation
///   - *ip_dest*: Ip address of the destination of the conversation
///   -  *prt_srg*: Source Port
///   -  *prt_dest*: Destination Port,
///   -  *protocol*: Protocol used in the conversation,
pub struct ConversationKey {
    ip_srg: IpAddr,
    ip_dest: IpAddr,
    prt_srg: u16,
    prt_dest: u16,
    protocol: Protocol,
}

impl ConversationKey {
    /// Create a new Conversation Key object instance and initialize its fields
    ///   - *ip_srg*: Ip address of the source of the conversation
    ///   - *ip_dest*: Ip address of the destination of the conversation
    ///   -  *prt_srg*: Source Port
    ///   -  *prt_dest*: Destination Port,
    ///   -  *protocol*: Protocol used in the conversation,
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
    /// Get the source ip address
    pub fn get_ip_srg(&self) -> IpAddr{ return self.ip_srg}
    /// Get the destination ip address
    pub fn get_ip_dest(&self) -> IpAddr{ return self.ip_dest}
    /// Get the source port
    pub fn get_prt_srg(&self) -> u16{ return self.prt_srg}
    /// Get the destination port
    pub fn get_prt_dest(&self) -> u16{ return self.prt_dest}
    /// Get the protol
    pub fn get_protocol(&self) -> Protocol{ return self.protocol}
}

#[derive(Debug, Clone, Copy)]
/// Filter object. It carries the information set by the user about which packet he/she is interested in seeing in the report
/// All the fields of the filter object can be set to None (meaning 'Any' 'Not to be filtered based on this field').
/// - *ip_srg*: a value different than None means that the user wants to see in the report only packets coming from *this* source ip address
///  -   *ip_dest*: a value different than None means that the user wants to see in the report only packets going to *this* destination ip address
///   -  *prt_srg*: a value different than None means that the user wants to see in the report only packets coming from *this* source port
///    - *prt_dest*: a value different than None means that the user wants to see in the report only packets coming from *this* destination port
///   -  *protocol*: a value different than None means that the user wants to see in the report only packets carrying *this* protocol

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
    /// Create a new Filter Object instance
   pub fn new() -> Self {
        return Filter {
            ip_srg: None,
            ip_dest: None,
            prt_srg: None,
            prt_dest: None,
            protocol: Protocol::None,
        };
    }
    /// Set the source ip address on which filter out packets
    pub fn set_ip_srg(&mut self, ip: IpAddr) {
        self.ip_srg = Some(ip);
    }
    /// Set the destination ip address on which filter out packets
    pub fn set_ip_dest(&mut self, ip: IpAddr) {
        self.ip_dest = Some(ip);
    }
    /// Set the source port on which filter out packets
    pub fn set_prt_srg(&mut self, prt: u16) {
        self.prt_srg = Some(prt);
    }
    /// Set the destination port on which filter out packets
    pub fn set_prt_dest(&mut self, prt: u16) {
        self.prt_dest = Some(prt);
    }

    /// Set the protocol on which filter out packets
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = protocol;
    }

    /// Get the source ip address on which filter out packets
    pub fn get_ip_srg(&self) -> Option<IpAddr> { return self.ip_srg}
    /// Get the destination ip address on which filter out packets
    pub fn get_ip_dest(&self) -> Option<IpAddr> { return self.ip_dest}
    /// Get the source port on which filter out packets
    pub fn get_prt_srg(&self) -> Option<u16> { return self.prt_srg}
    /// Set the destination port on which filter out packets
    pub fn get_prt_dest(&self) -> Option<u16> { return self.prt_dest}
    //pub fn get_protocol(&self) -> Protocol{ return self.protocol}
}

/*
*  PROTOCOLS HANDLE FUNCTIONS
*
*/
/// Checks whether the packet carried by the Transport Layer Packet ('packet') is a DNS packet or not
fn handle_dns_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    match dns_parser::Packet::parse(packet) {
        Ok(_) => {
            PacketInfo::set_protocol(new_packet_info, Protocol::Dns);
            if filter.protocol == Protocol::Dns {
                new_packet_info.set_printed();
            }

        }
        Err(_) => {}
    }
}
/// Checks whether the packet carried by the Transport Layer Packet ('packet') is a TLS packet or not
fn handle_tls_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {

    if tls_parser::parse_tls_plaintext(packet).is_ok() || tls_parser::parse_tls_encrypted(packet).is_ok()
    {
            PacketInfo::set_protocol(new_packet_info, Protocol::Tls);
            //println!("TLS plaintext {:?}", tls_packet.1);
            if filter.protocol == Protocol::Tls {
                new_packet_info.set_printed();
            }
        }

}

/// Function to handle an UDP packet parsing it accordingly
fn handle_udp_packet(packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        // Extract the source and destination port
        let prt_srg = udp.get_source();
        let prt_dest = udp.get_destination();

        // Save them in the PacketInfo structure

        if filter.protocol == Protocol::Udp {
            new_packet_info.set_printed();
        }


        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Udp);

        handle_dns_packet(udp.payload(), new_packet_info, filter);
    }
        //  else {
   //     println!("Malformed UDP Packet");
   // }
}
/// Function to handle an ICMPv4 packet parsing it accordingly
fn handle_icmp_packet( packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmp_packet = IcmpPacket::new(packet);

    if let Some(_) = icmp_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV4);
        if filter.protocol == Protocol::IcmpV4 {
            new_packet_info.set_printed();
        }

    }
   //  else {
   //     println!("Malformed ICMP Packet");
   // }
}

/// Function to handle an ICMPv6 packet parsing it accordingly
fn handle_icmpv6_packet( packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let icmpv6_packet = Icmpv6Packet::new(packet);

    if let Some(_) = icmpv6_packet {
        // Save the protocol type in the PacketInfo structure
        PacketInfo::set_protocol(new_packet_info, Protocol::IcmpV6);
        if filter.protocol == Protocol::IcmpV6 {
            new_packet_info.set_printed();
        }
    }
   // else {
   //     println!("Malformed ICMPv6 Packet");
   // }
}
/// Function to handle an TCP packet parsing it accordingly
fn handle_tcp_packet( packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        // Extract the source and destination ports
        let prt_srg = tcp.get_source();
        let prt_dest = tcp.get_destination();

        if filter.protocol == Protocol::Tcp {
            new_packet_info.set_printed();
        }

        // Save them in the PacketInfo structure
        PacketInfo::set_porta_sorgente(new_packet_info, prt_srg);
        PacketInfo::set_porta_destinazione(new_packet_info, prt_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Tcp);

        // Check if the protocol carried is TLS or DNS
        handle_tls_packet(tcp.payload(), new_packet_info, filter);
        handle_dns_packet(tcp.payload(), new_packet_info, filter);

        // Check if the application protocol is HTTP or HTTPS
        match new_packet_info.prt_dest {
            80 => {
                if filter.protocol == Protocol::Http {
                    new_packet_info.set_printed();
                }
                PacketInfo::set_protocol(new_packet_info, Protocol::Http);
            }
            443 => {
                if filter.protocol == Protocol::Https {
                    new_packet_info.set_printed();
                }
                PacketInfo::set_protocol(new_packet_info, Protocol::Https);
            }
            _ => {}
        }
    } else {
        println!("Malformed TCP Packet");
    }
}
/// Function to handle a generic Transport Layer packet. Based on the type of protocol used it calls specific functions to handle it accordingly
fn handle_transport_protocol(protocol: IpNextHeaderProtocol, packet: &[u8], new_packet_info: &mut PacketInfo, filter: &Filter) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
             handle_udp_packet( packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Tcp => {
              handle_tcp_packet(packet, new_packet_info, filter)
        }
        IpNextHeaderProtocols::Icmp => {

            handle_icmp_packet(packet, new_packet_info, filter);
        }
        IpNextHeaderProtocols::Icmpv6 => {

            handle_icmpv6_packet( packet, new_packet_info, filter);
        }

        _ => {

            //println!("Unknown transport level protocol {}!", protocol);
        }
    }
}
/// Function to handle an IPV4 packet parsing it accordingly.
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


        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);

        handle_transport_protocol(

            header.get_next_level_protocol(),
            header.payload(),
            new_packet_info,
            filter,
        );
    } //else {
       // println!("Malformed IPv4 Packet");
    //}
}
/// Function to handle an ipv6 packet parsing it accordingly
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

            header.get_next_header(),
            header.payload(),
            new_packet_info,
            filter,
        );
    } //else {
        //println!("Malformed IPv6 Packet");
    //}
}
/// Function to handle an ARP packet parsing it accordingly
fn handle_arp_packet(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    let header = ArpPacket::new(ethernet.payload());

    if let Some(header) = header {
        let ip_sorg = IpAddr::V4(header.get_sender_proto_addr());
        let ip_dest = IpAddr::V4(header.get_target_proto_addr());

        // If there is a filter on the protocol and it is IPv4
        if filter.protocol == Protocol::Arp {
            new_packet_info.set_printed();
        }


        PacketInfo::set_ip_sorgente(new_packet_info, ip_sorg);
        PacketInfo::set_ip_destinazione(new_packet_info, ip_dest);
        PacketInfo::set_protocol(new_packet_info, Protocol::Arp);

    } //else {
      //  println!("Malformed ARP Packet");
    //}
}

/// Function to handle an ethernet packet parsing it accordingly
pub fn handle_ethernet_frame(ethernet: &EthernetPacket, new_packet_info: &mut PacketInfo, filter: &Filter) {
    PacketInfo::set_dim(new_packet_info, ethernet.packet().len());

    // If there is no filter on the protocol, packet is set printed
    if filter.protocol == Protocol::None {
        new_packet_info.set_printed();
    }

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, new_packet_info, filter),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, new_packet_info, filter),
        EtherTypes::Arp => handle_arp_packet(ethernet, new_packet_info, filter),
        _ => {
            //println!("unknown lvl 3 protocol");
        }
    }
}

/// Function to handle particular interfaces pointed out by the creators of 'Libpnet'
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
