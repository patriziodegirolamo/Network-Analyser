use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use prettytable::{Cell, Row, Table};
use std::thread;
use std::time::Duration;
use crate::packet_handle::{ConversationKey, ConversationStats, PacketInfo};
use crate::{Status, StatusValue};

pub struct Reporter{
    filename: String,
    time_interval: usize,
    status_sniffing: Arc<Status>,
    convs_summaries: HashMap<ConversationKey, ConversationStats>,
    status_writing: Arc<Mutex<bool>>,

    //receiver channel to receive packet_infos from the sniffer
    receiver_channel: Receiver<PacketInfo>
}

impl Reporter{
    pub fn new(filename: String,
               time_interval: usize,
               status_sniffing: Arc<Status>,
               receiver_channel: Receiver<PacketInfo>
    ) -> Self{
        Self{
            filename,
            time_interval,
            status_sniffing,
            convs_summaries: HashMap::new(),
            status_writing: Arc::new(Mutex::new(false)),
            receiver_channel
        }
    }

    pub fn reporting(&mut self){
        loop {
            let status_sniffing_value = self.status_sniffing.mutex.lock().unwrap();
            match *status_sniffing_value {
                StatusValue::Running => {
                    println!("Reporter is running")
                }
                StatusValue::Paused => {
                    println!("Reporter is paused");
                }
                StatusValue::Exit => {
                    println!("Reporter exit");
                    break;
                }
            }
            thread::sleep(Duration::from_secs(3));
        }
    }
}


/*
*  PRINT on FiLE FUNCTIONS
*
*/
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
            Cell::new(&*key.get_ip_srg().to_string()), // s  : String -> *s : str (via Deref<Target=str>) -> &*s: &str
            Cell::new(&*key.get_prt_srg().to_string()),
            Cell::new(&*key.get_ip_dest().to_string()),
            Cell::new(&*key.get_prt_dest().to_string()),
            Cell::new(&*key.get_protocol().to_string()),
            Cell::new(&*elem.get_tot_bytes().to_string()),
            Cell::new(&*elem.get_starting_time().unwrap().as_nanos().to_string()),
            Cell::new(&*elem.get_ending_time().unwrap().as_nanos().to_string()),
        ]));
    }

    // Print the table on file
    table.print(file).expect("Error");
}
