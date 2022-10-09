use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Receiver, Sender};
use prettytable::{Cell, Row, Table};
use std::thread;
use std::time::{Duration, SystemTime};
use crate::packet_handle::{ConversationKey, ConversationStats, PacketInfo};
use crate::{Protocol, Status, StatusValue};

pub struct Reporter {
    filename: String,
    final_filename: String,
    time_interval: usize,
    status_sniffing: Arc<Status>,
    convs_summaries: HashMap<ConversationKey, ConversationStats>,
    convs_final: HashMap<ConversationKey, ConversationStats>,
    //receiver channel to receive packet_infos from the sniffer
    receiver_channel: Receiver<PacketInfo>,
    sender_timer: Sender<()>,
    status_writing: Arc<Mutex<bool>>,
    initial_time: SystemTime
}

impl Reporter {
    pub fn new(filename: String,
               final_filename: String,
               time_interval: usize,
               status_sniffing: Arc<Status>,
               receiver_channel: Receiver<PacketInfo>,
               sender_timer: Sender<()>,
               status_writing: Arc<Mutex<bool>>,
               initial_time: SystemTime,
    ) -> Self {
        Self {
            filename,
            final_filename,
            time_interval,
            status_sniffing,
            convs_summaries: HashMap::new(),
            convs_final: HashMap::new(),
            receiver_channel,
            sender_timer,
            status_writing,
            initial_time
        }
    }

/*    // Updates collection of all conversations to write in final report
    fn update_convs_final(&mut self, convs_summaries: &HashMap<ConversationKey, ConversationStats>) {

        if !self.convs_summaries.is_empty() { // if there are conversations
            for (key, elem) in convs_summaries {
                // Creates a new key for final collection
                let key_final = ConversationKey::new_key(
                    key.get_ip_srg(),
                    key.get_ip_dest(),
                    key.get_prt_srg(),
                    key.get_prt_dest(),
                    key.get_protocol()
                );

                // If key is already presents, updates the element otherwise inserts it
                self.convs_final.entry(key_final)
                    .and_modify(|entry| {
                        entry.set_tot_bytes(elem.get_tot_bytes());
                        entry.set_ending_time(elem.get_ending_time().unwrap());
                        entry.set_tot_packets(elem.get_tot_bytes());
                    })
                    .or_insert(ConversationStats::new(
                        elem.get_tot_bytes(),
                        elem.get_starting_time().unwrap(),
                        elem.get_ending_time().unwrap(),
                        elem.get_tot_bytes()));
            }
        }
    }*/

    pub fn reporting(&mut self) {
        let mut status = StatusValue::Exit;

        //TODO: spostare la open nello start e gestire errore
        let mut file = open_file(&self.filename).unwrap();
        let mut write_header = true;
        let mut n_packets = 0;
        loop {

            if !self.convs_summaries.is_empty() // If there are conversation to write
            {
                let mut status_writing_value = self.status_writing.lock().unwrap();
                if *status_writing_value == true {
                    println!("Scrivo su report!");
                    *status_writing_value = false;
                    //simple_write(&self, &mut file);
                    write_summaries(&mut file, &self.convs_summaries, &self.initial_time, write_header);
                    //write_header = false;

                    // Before clearing convs_summeries updates convs_final to produce final report
                    //self.update_convs_final(&self.convs_summaries);
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
                        if !self.convs_summaries.is_empty() {// Before exit update the report one last time and produces final report
                            println!("Scrivo su report!");
                            write_summaries(&mut file, &self.convs_summaries, &self.initial_time, write_header);
                        }
                        println!("Reporter exit, TOT Packets: {}", n_packets);
                        // Alert the timer thread
                        self.sender_timer.send(()).unwrap();

                        // Writes all conversations in final report
                        println!("Write final report");
                        let mut final_file = open_file(&self.final_filename).unwrap();
                        write_final_report(
                            &mut final_file,
                            &self.convs_final
                        );

                        return;
                    }
                }
            }
            //SE E' ARRIVATO QUI, LO STATUS E' RUNNING

            while let Ok(new_packet_info) = self.receiver_channel.try_recv(){
                //n_packets += 1;
                if new_packet_info.get_printed(){
                    n_packets += 1;
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
                            entry.set_tot_packets(1);
                        })
                        .or_insert(ConversationStats::new(
                            new_packet_info.get_dim(),
                            new_packet_info.get_time().unwrap(),
                            new_packet_info.get_time().unwrap(),
                        1));

                    // Updates also convs_final
                    self.convs_final.entry(key)
                        .and_modify(|entry| {
                            entry.set_tot_bytes(new_packet_info.get_dim());
                            entry.set_ending_time(new_packet_info.get_time().unwrap());
                            entry.set_tot_packets(1);
                        })
                        .or_insert(ConversationStats::new(
                            new_packet_info.get_dim(),
                            new_packet_info.get_time().unwrap(),
                            new_packet_info.get_time().unwrap(),
                            1));
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

//TODO: handle the format!
fn write_summaries(file: &mut File, convs_summaries: &HashMap<ConversationKey, ConversationStats>, time: &SystemTime, write_header: bool) {
    let mut table = Table::new();

    let secs : u64 = time.elapsed().unwrap().as_secs();
    let secs_str : String = secs.to_string();

    if write_header {
        table.set_titles(Row::new(vec![
            Cell::new("NEW REPORT").style_spec("bc")
        ]));

        table.add_row(Row::new(vec![
            Cell::new("Time").style_spec("b"),
            Cell::new("Ip_srg").style_spec("b"),
            Cell::new("Prt_srg").style_spec("b"),
            Cell::new("Ip_dest").style_spec("b"),
            Cell::new("Prt_dest").style_spec("b"),
            Cell::new("Protocol").style_spec("b"),
            Cell::new("Tot_bytes").style_spec("b"),
            Cell::new("Starting_time").style_spec("b"),
            Cell::new("Ending_time").style_spec("b"),
            Cell::new("Tot_packets").style_spec("b"),
        ]));
    }

    if !convs_summaries.is_empty(){

        // Creo un vettore in cui inserisco le conversazioni come tupla (Key, Stats)
        let mut sorted_conv: Vec<(ConversationKey, ConversationStats)> = Vec::new();
        for(key, elem) in convs_summaries {
            sorted_conv.push((*key, *elem));
        }
        // ordino per starting_time
        sorted_conv.sort_by(|a,b|
            a.1.get_starting_time().cmp(&b.1.get_starting_time()));

        for conv in sorted_conv {
            let start = conv.1.get_starting_time().unwrap();
            let end = conv.1.get_ending_time().unwrap();
            let start_format = format!("{}.{} secs", start.as_secs(), start.as_millis());
            let end_format = format!("{}.{} secs", end.as_secs(), end.as_millis());
            //TODO: gestire porta nulla (zero) e ip (None)

            // handle default values => replace with "-"
            let prt_src;
            let normalized_prt_src = match conv.0.get_prt_srg() {
                0 => "-",
                _ => {
                    prt_src = conv.0.get_prt_srg().to_string();
                    &prt_src
                }
            };
            let prt_dst;
            let normalized_prt_dst = match conv.0.get_prt_dest() {
                0 => "-",
                _ => {
                    prt_dst = conv.0.get_prt_dest().to_string();
                    &prt_dst
                }
            };

            table.add_row(Row::new(vec![
                Cell::new(&*secs_str),
                Cell::new(&*conv.0.get_ip_srg().to_string()), // s  : String -> *s : str (via Deref<Target=str>) -> &*s: &str
                Cell::new(normalized_prt_src),
                Cell::new(&*conv.0.get_ip_dest().to_string()),
                Cell::new(normalized_prt_dst),
                Cell::new(&*conv.0.get_protocol().to_string()),
                Cell::new(&*conv.1.get_tot_bytes().to_string()),
                Cell::new(&*start_format),
                Cell::new(&*end_format),
                Cell::new(&*conv.1.get_tot_packets().to_string()),
            ]));
        }
        table.print(file).expect("Error");
    }

}

fn write_final_report(file: &mut File, convs_final: &HashMap<ConversationKey, ConversationStats>) {

    let mut table = Table::new();

    table.set_titles(Row::new(vec![
        Cell::new("FINAL REPORT").style_spec("bc")
    ]));

    table.add_row(Row::new(vec![
        Cell::new("Ip_srg").style_spec("b"),
        Cell::new("Prt_srg").style_spec("b"),
        Cell::new("Ip_dest").style_spec("b"),
        Cell::new("Prt_dest").style_spec("b"),
        Cell::new("Protocol").style_spec("b"),
        Cell::new("Tot_bytes").style_spec("b"),
        Cell::new("Starting_time").style_spec("b"),
        Cell::new("Ending_time").style_spec("b"),
        Cell::new("Tot_packets").style_spec("b"),
    ]));

    if !convs_final.is_empty(){

        // Creo un vettore in cui inserisco le conversazioni come tupla (Key, Stats)
        let mut sorted_conv: Vec<(ConversationKey, ConversationStats)> = Vec::new();
        for(key, elem) in convs_final {
            sorted_conv.push((*key, *elem));
        }
        // ordino per starting_time
        sorted_conv.sort_by(|a,b|
            a.1.get_starting_time().cmp(&b.1.get_starting_time()));

        for conv in sorted_conv {
            let start = conv.1.get_starting_time().unwrap();
            let end = conv.1.get_ending_time().unwrap();
            let start_format = format!("{}.{} secs", start.as_secs(), start.as_millis());
            let end_format = format!("{}.{} secs", end.as_secs(), end.as_millis());

            // handle default values => replace with "-"
            let prt_src;
            let normalized_prt_src = match conv.0.get_prt_srg() {
                0 => "-",
                _ => {
                    prt_src = conv.0.get_prt_srg().to_string();
                    &prt_src
                }
            };
            let prt_dst;
            let normalized_prt_dst = match conv.0.get_prt_dest() {
                0 => "-",
                _ => {
                    prt_dst = conv.0.get_prt_dest().to_string();
                    &prt_dst
                }
            };

            table.add_row(Row::new(vec![
                Cell::new(&*conv.0.get_ip_srg().to_string()), // s  : String -> *s : str (via Deref<Target=str>) -> &*s: &str
                Cell::new(normalized_prt_src),
                Cell::new(&*conv.0.get_ip_dest().to_string()),
                Cell::new(normalized_prt_dst),
                Cell::new(&*conv.0.get_protocol().to_string()),
                Cell::new(&*conv.1.get_tot_bytes().to_string()),
                Cell::new(&*start_format),
                Cell::new(&*end_format),
                Cell::new(&*conv.1.get_tot_packets().to_string()),
            ]));
        }
        table.print(file).expect("Error");
    }
}

fn is_paused(state: &StatusValue) -> bool {
    return match state {
        StatusValue::Running => false,
        StatusValue::Paused => true,
        StatusValue::Exit => false
    };
}