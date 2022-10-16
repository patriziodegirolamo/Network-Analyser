use std::collections::HashSet;
use std::sync::{Arc};
use std::sync::mpsc::Sender;
use pnet::packet::ethernet::{EthernetPacket};
use std::time::{SystemTime};
use pcap::{Active, Capture, Device};
use crate::packet_handle::PacketInfo;
use crate::{Filter, packet_handle, Protocol, Status, StatusValue};

/// Sniffer object.
/// It gets raw packets from the 'Network Interface', handle them accordingly.
/// The most meaningful information extracted by each packet are saved in a 'PacketInfo' structure, then send to
/// the 'Reporter' to update the report.
///     - *interface*: Network interface,
///     - *filter*: filter selected by the user. The sniffing process needs to take it in consideration.
///     - *sender_channel*: sender end of the channel shared with the reporter. The sniffer sends a 'PacketInfo' for each packet that gets from the interface
///     - *receiver_channel*: receiver end of the channel shared with the network interface. From this channel the Sniffer gets raw packets.
///     - *status*: status of the application ['Running', 'Exit', 'Pause']
///     - *time*: time on which the application started
pub struct Sniffer {
    interface: Device,
    filter: Filter,
    //sender channel to send packet_infos to the reporter
    sender_channel: Sender<PacketInfo>,

    //receiver channel to receive raw_packet from the lvl2 interface
    receiver_channel: Capture<Active>,

    status: Arc<Status>,
    time: SystemTime,
}

impl Sniffer {
    /// Create a new instance of the Sniffer object
    ///     - *interface*: Network Interface,
    ///     - *filter*: filter selected by the user. The sniffing process needs to take it in consideration.
    ///     - *sender_channel*: sender end of the channel shared with the reporter. The sniffer sends a 'PacketInfo' for each packet that gets from the interface
    ///     - *receiver_channel*: receiver end of the channel shared with the network interface. From this channel the Sniffer gets raw packets.
    ///     - *status*: status of the application ['Running', 'Exit', 'Pause']
    ///     - *time*: time on which the application started
    pub fn new(interface: Device, filter: Filter, sender_channel: Sender<PacketInfo>, receiver_channel: Capture<Active>, status: Arc<Status>, time: SystemTime) -> Self {
        Self { interface, filter, sender_channel, receiver_channel, status, time }
    }

    /// Sniffing function.
    /// It can be called only once.
    /// At each iteration the Sniffer gets a packet from the Network Interface.
    /// In 'Running' state it handles it parsing it and extracting the information needed to create a PacketInfo object. Then it sends it through the channel to the Reporter.
    /// In 'Pause' state it discards all the packets that it gets
    /// In 'Exit' state it returns
    pub fn sniffing(mut self) {
        let mut status;

        loop {
            // Get a packet from the interface
            match self.receiver_channel.next_packet() {
                Ok(packet) => {
                    {  // Check the status of the application
                        let status_value = self.status.mutex.lock().unwrap();
                        status = *status_value;
                    }

                    match status {
                        StatusValue::Running => {
                            // Packet arrival time
                            let initial_time = SystemTime::elapsed(&self.time).expect("TIME ERROR");

                            // Create a data structure to host the information got from the packet
                            let mut new_packet_info = PacketInfo::new();

                            // Set arrival packet time
                            PacketInfo::set_time(&mut new_packet_info, initial_time);

                            // Handle particular interfaces
                            if !packet_handle::handle_particular_interfaces(&self.interface, packet.data, &mut new_packet_info, &self.filter) {
                                packet_handle::handle_ethernet_frame(&EthernetPacket::new(packet.data).unwrap(), &mut new_packet_info, &self.filter);
                            }
                            // Send the packet info to the Sniffer
                            self.sender_channel.send(new_packet_info).unwrap();
                        }
                        StatusValue::Paused => {
                            // Discard all the packets got. (If the reporter gets actually paused the packets that arrive in the meanwhile would be put in the channel buffer, but what we want
                            // to do is discard them since we are not interested in packets that arrives while the application is paused-
                            continue;
                        }
                        StatusValue::Exit => {
                            return;
                        }
                    }

                }
                Err(_) => {
                    {  // Check the status of the application
                        let status_value = self.status.mutex.lock().unwrap();
                        status = *status_value;
                    }

                    match status {
                        StatusValue::Exit => {
                            return;
                        }
                        _ => continue
                    }
                },
           }
        }
    }
}