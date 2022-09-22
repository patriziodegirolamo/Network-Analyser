use std::sync::Arc;
use std::sync::mpsc::Sender;
use pnet_datalink::DataLinkReceiver;
use crate::packet_handle::PacketInfo;
use crate::Status;

pub struct Sniffer{
    //sender channel to send packet_infos to the reporter
    sender_channel: Sender<PacketInfo>,

    //receiver channel to receive raw_packet from the lvl2 interface
    receiver_channel: Box<dyn DataLinkReceiver>,

    status: Arc<Status>
}

impl Sniffer{
    pub fn new(sender_channel: Sender<PacketInfo>, receiver_channel: Box<dyn DataLinkReceiver>, status: Arc<Status>) -> Self{
        Self{ sender_channel, receiver_channel, status }
    }

    pub fn sniffing(&mut self){
        return;
    }
}