use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::sync::{Arc, MutexGuard};
use std::sync::mpsc::Sender;
use pnet_datalink::{DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket};
use std::thread;
use std::time::{Duration, SystemTime};
use crate::packet_handle::PacketInfo;
use crate::{Filter, packet_handle, Protocol, Status, StatusValue};

pub struct Sniffer {
    interface: NetworkInterface,
    filter: Filter,
    //sender channel to send packet_infos to the reporter
    sender_channel: Sender<PacketInfo>,

    //receiver channel to receive raw_packet from the lvl2 interface
    receiver_channel: Box<dyn DataLinkReceiver>,

    status: Arc<Status>,
    time: SystemTime,
}

impl Sniffer {
    pub fn new(interface: NetworkInterface, filter: Filter, sender_channel: Sender<PacketInfo>, receiver_channel: Box<dyn DataLinkReceiver>, status: Arc<Status>, time: SystemTime) -> Self {
        Self { interface, filter, sender_channel, receiver_channel, status, time }
    }

    pub fn sniffing(&mut self) {
        let mut status = StatusValue::Exit;

        //TODO: serve per un check visivo dei pacchetti. Non è effettivamente utile!
        let mut buffer_packets = vec![];

        loop {

            match self.receiver_channel.next() {
                Ok(packet) => {
                    {
                        let status_value = self.status.mutex.lock().unwrap();
                        status = *status_value;
                    }

                    match status {
                        StatusValue::Running => {
                            // Packet arrival time
                            let initial_time = SystemTime::elapsed(&self.time).expect("TIME ERROR");

                            //println!("packet arrived at: {}.{} secs", initial_time.as_secs(), initial_time.as_millis());
                            // Create a data structure to host the information got from the packet
                            let mut new_packet_info = PacketInfo::new();

                            // Set arrival packet time
                            PacketInfo::set_time(&mut new_packet_info, initial_time);

                            // se è un caso particolare, faccio l'handle con il pacchetto modificato a dovere
                            //altrimenti faccio l'handle normale
                            if !packet_handle::handle_particular_interfaces(&self.interface, packet, &mut new_packet_info, &self.filter) {
                                packet_handle::handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &mut new_packet_info, &self.filter);
                            }
                            buffer_packets.push(new_packet_info.clone());
                            self.sender_channel.send(new_packet_info).unwrap();
                        }
                        StatusValue::Paused => {
                            continue;
                        }
                        StatusValue::Exit => {
                            // Counts also not printed packets
                            println!("Sniffer exit, TOT Packets: {}", buffer_packets.len());
                            let protocols : HashSet<Protocol> = buffer_packets.into_iter().map(|p| p.get_protocol()).collect();
                            println!("protocols: {:?}", protocols);
                            return;
                        }
                    }

                }
                Err(e) => println!("packetdump: unable to receive packet: {}", e),      //TODO: GESTIRE ERRORE (settare status ad exit e ritornare)
            }
        }
    }
}