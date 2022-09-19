// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod packet_handle;
mod network_handle;

/// This example shows a basic packet logger using libpnet
extern crate pnet;

use std::collections::HashMap;
use pnet_datalink::{self as datalink};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;
use pnet_datalink::Channel::Ethernet as Ethernet;

//use std::env;
use std::time::{SystemTime};
use packet_handle::{ConversationStats, ConversationKey, PacketInfo};

fn main() {
    let mut convs_summaries: HashMap<ConversationKey, ConversationStats> = HashMap::new();


    let (interface, time_interval, filename, filter) = network_handle::fast_init_sniffing();
    //let (interface, time_interval, filename, filter) = init_sniffing();

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
        match rx.next() {
            Ok(packet) => {
                // Packet arrival time
                let intial_time = SystemTime::now().duration_since(time_0).expect("TIME ERROR");

                // Create a data structure to host the information got from the packet
                let mut new_packet_info = PacketInfo::new();

                // Set arrival packet time
                PacketInfo::set_time(&mut new_packet_info, intial_time);

                // se è un caso particolare, faccio l'handle con il pacchetto modificato a dovere
                //altrimenti faccio l'handle normale
                if !network_handle::handle_particular_interfaces(&interface, packet, &mut new_packet_info, &filter){
                    packet_handle::handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &mut new_packet_info, &filter);
                }

                if new_packet_info.get_printed(){
                    // Create the key of the packet considering (ip_sorg, ip_dest, port_sorg, port_dest, prot)
                    let key = ConversationKey::new_key(new_packet_info.get_ip_sorgente().unwrap(),
                                                       new_packet_info.get_ip_destinazione().unwrap(),
                                                       new_packet_info.get_porta_sorgente(),
                                                       new_packet_info.get_porta_destinazione(),
                                                       new_packet_info.get_protocol());
                    // If the packet belongs to a conversation already present in the map, update the stats, otherwise add a new record
                    convs_summaries.entry(key)
                        .and_modify(|entry| {
                            entry.set_tot_bytes(new_packet_info.get_dim());
                            entry.set_ending_time(new_packet_info.get_time().unwrap());
                        })
                        .or_insert(ConversationStats::new(
                                    new_packet_info.get_dim(),
                                    new_packet_info.get_time().unwrap(),
                                    new_packet_info.get_time().unwrap()));
                }
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
        if i == 60 {
            break;
        }
        i += 1;
    }

    let mut file = packet_handle::open_file(filename).expect("ERRORE FILE");
    packet_handle::write_summaries(&mut file, convs_summaries);
}