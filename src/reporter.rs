use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Receiver, Sender};
use prettytable::{Cell, Row, Table};
use std::thread;
use std::time::{Duration, SystemTime};
use crate::packet_handle::{ConversationKey, ConversationStats, PacketInfo};
use crate::{Status, StatusValue};

pub struct Reporter {
    filename: String,
    time_interval: usize,
    status_sniffing: Arc<Status>,
    convs_summaries: HashMap<ConversationKey, ConversationStats>,
    //receiver channel to receive packet_infos from the sniffer
    receiver_channel: Receiver<PacketInfo>,
    sender_timer: Sender<()>,
    status_writing: Arc<Mutex<bool>>,
    initial_time: SystemTime
}

impl Reporter {
    pub fn new(filename: String,
               time_interval: usize,
               status_sniffing: Arc<Status>,
               receiver_channel: Receiver<PacketInfo>,
               sender_timer: Sender<()>,
               status_writing: Arc<Mutex<bool>>,
               initial_time: SystemTime,
    ) -> Self {
        Self {
            filename,
            time_interval,
            status_sniffing,
            convs_summaries: HashMap::new(),
            receiver_channel,
            sender_timer,
            status_writing,
            initial_time
        }
    }

    pub fn reporting(&mut self) {
        let mut status = StatusValue::Exit;

        //TODO: spostare la open nello start e gestire errore
        let mut file = open_file(&self.filename).unwrap();
        loop {

            {
                let mut status_writing_value = self.status_writing.lock().unwrap();
                if *status_writing_value == true {
                    println!("Scrivo su report!");
                    *status_writing_value = false;
                    //simple_write(&self, &mut file);
                    //todo: LA PRIMA VOLTA SCRIVE A VUOTO!
                    write_summaries(&mut file, &self.convs_summaries, &self.initial_time);
                    self.convs_summaries.clear();
                }
            }

            {
                let mut status_sniffing_value = self.status_sniffing.mutex.lock().unwrap();

                match *status_sniffing_value {
                    StatusValue::Running => {
                        if status != StatusValue::Running {
                            println!("Reporter is running");
                            status = StatusValue::Running;
                        }
                    }
                    StatusValue::Paused => {
                        println!("Reporter is paused");
                        status = StatusValue::Paused;
                        status_sniffing_value = self.status_sniffing.cvar.wait_while(status_sniffing_value, |s| is_paused(&*s)).unwrap();
                    }
                    StatusValue::Exit => {
                        println!("Reporter exit");
                        self.sender_timer.send(()).unwrap();
                        return;
                    }
                }
            }
            //SE E' ARRIVATO QUI, LO STATUS E' RUNNING

            while let Ok(new_packet_info) = self.receiver_channel.try_recv(){

                if new_packet_info.get_printed(){
                    // Create the key of the packet considering (ip_sorg, ip_dest, port_sorg, port_dest, prot)
                    let key = ConversationKey::new_key(new_packet_info.get_ip_sorgente().unwrap(),
                                                       new_packet_info.get_ip_destinazione().unwrap(),
                                                       new_packet_info.get_porta_sorgente(),
                                                       new_packet_info.get_porta_destinazione(),
                                                       new_packet_info.get_protocol());
                    // If the packet belongs to a conversation already present in the map, update the stats, otherwise add a new record
                    self.convs_summaries.entry(key)
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
        }
    }
}


/*
*  PRINT on FiLE FUNCTIONS
*
*/
fn open_file(filename: &String) -> io::Result<File> {
    //TODO: GESTIRE ERRORE APERTURA FILE ???
    return File::options().write(true).truncate(true).create(true).open(filename);
}

fn simple_write(reporter: &Reporter, file: &mut File){
    let secs : u64 = reporter.initial_time.elapsed().unwrap().as_secs();
    let secs_str : String = secs.to_string();
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new(&*secs_str),
    ]));
    table.print(file).unwrap();
}
fn write_summaries(file: &mut File, convs_summaries: &HashMap<ConversationKey, ConversationStats>, time: &SystemTime) {

    // Create the table
    let mut table = Table::new();

    let secs : u64 = time.elapsed().unwrap().as_secs();
    let secs_str : String = secs.to_string();

    table.add_row(Row::new(vec![
        Cell::new("Time").style_spec("b"),
        Cell::new(&*secs_str)
    ]));

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


    for (key, elem) in convs_summaries {
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

fn is_paused(state: &StatusValue) -> bool {
    return match state {
        StatusValue::Running => false,
        StatusValue::Paused => true,
        StatusValue::Exit => false
    };
}