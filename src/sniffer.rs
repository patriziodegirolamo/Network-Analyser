use std::sync::{Arc, MutexGuard};
use std::sync::mpsc::Sender;
use pnet_datalink::DataLinkReceiver;
use std::thread;
use std::time::Duration;
use crate::packet_handle::PacketInfo;
use crate::{Status, StatusValue};

pub struct Sniffer {
    //sender channel to send packet_infos to the reporter
    sender_channel: Sender<PacketInfo>,

    //receiver channel to receive raw_packet from the lvl2 interface
    receiver_channel: Box<dyn DataLinkReceiver>,

    status: Arc<Status>,
}

impl Sniffer {
    pub fn new(sender_channel: Sender<PacketInfo>, receiver_channel: Box<dyn DataLinkReceiver>, status: Arc<Status>) -> Self {
        Self { sender_channel, receiver_channel, status }
    }

    pub fn sniffing(&mut self) {
        loop {
            {
                let status_value = self.status.mutex.read().unwrap();
                match *status_value {
                    StatusValue::Running => {
                        println!("Sniffer is running")
                    }
                    StatusValue::Paused => {
                        println!("Sniffer is paused");
                    }
                    StatusValue::Exit => {
                        println!("Sniffer exit");
                        return;
                    }
                }
            }
            thread::sleep(Duration::from_secs(2));

        }
    }
}