use std::collections::HashMap;
use std::fs::File;
use std::{io, thread};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime};
use crate::packet_handle::{ConversationKey, ConversationStats, PacketInfo};
use crate::{Filter,  Status, StatusValue};
use tabled::{Table, Tabled, Style, Width, Modify, Disable};
use tabled::object::{Rows,  Columns};
use tabled::style::Border;
use std::io::Write;

#[derive(Tabled)]
struct ConvTabled{
    time: String,
    ip_srg: String,
    prt_srg: String,
    ip_dest: String,
    prt_dest: String,
    protocol: String,
    tot_bytes: String,
    starting_time: String,
    ending_time: String,
    tot_packets: String,
}
impl ConvTabled{
    fn new( time: String,
            ip_srg: String,
            prt_srg: String,
            ip_dest: String,
            prt_dest: String,
            protocol: String,
            tot_bytes: String,
            starting_time: String,
            ending_time: String,
            tot_packets: String)
        -> ConvTabled{
        ConvTabled{
            time, ip_srg, prt_srg, ip_dest, prt_dest, protocol, tot_bytes, starting_time, ending_time, tot_packets
        }
    }
}
/// Reporter object. It gets 'PacketInfo's from the 'Sniffer' object through the 'receiver_channel'.
/// Every 'time_interval' seconds it prints on the 'filename' file the report of the conversations happened in the last time interval.
/// In 'pause' mode stops taking packets from the channel and stops updating the report.
/// In 'exit' mode writes on the report the last update and creates a final report with all the conversations happened.
/// - *filename*: name of the report file (.exe)
/// - *time_interval*: number of seconds before updating the report
/// - *status_sniffing*: status of the application ['Running', 'Exit', 'Pause']
/// - *receiver_channel*: receiver end of the channel shared with the Sniffer thread
/// - *status_writing*: status shared with the Timer thread. When set to 'True' the reporter needs to update the report
/// - *initial_time*: when the application began sniffing
/// - *filter*: information on which packets the user is interested on see in the report
pub struct Reporter {
    filename: String,
    final_filename: String,
    time_interval: usize,
    status_sniffing: Arc<Status>,
    convs_summaries: HashMap<ConversationKey, ConversationStats>,
    convs_final: HashMap<ConversationKey, ConversationStats>,
    receiver_channel: Receiver<PacketInfo>,
    status_writing: Arc<Mutex<bool>>,
    initial_time: SystemTime,
    filter: Filter,
}

impl Reporter {
    /// Initialize the Reporter object
    /// - *filename*: name of the report file (.exe)
    /// - *time_interval*: number of seconds before updating the report
    /// - *status_sniffing*: status of the application ['Running', 'Quit', 'Pause']
    /// - *receiver_channel*: receiver end of the channel shared with the Sniffer thread
    /// - *initial_time*: when the application began sniffing
    /// - *filter*: information on which packets the user is interested on see in the report
    pub fn new(filename: String,
               final_filename: String,
               time_interval: usize,
               status_sniffing: Arc<Status>,
               receiver_channel: Receiver<PacketInfo>,
               //status_writing: Arc<Mutex<bool>>,
               initial_time: SystemTime,
               filter: Filter,
    ) -> Self {
        Self {
            filename,
            final_filename,
            time_interval,
            status_sniffing,
            convs_summaries: HashMap::new(),
            convs_final: HashMap::new(),
            receiver_channel,

            status_writing:Arc::new(Mutex::new(false)),
            initial_time,
            filter
        }
    }
    /// Function used to perform the reporting.
    /// It can be called only once. It returns when the status goes to 'Quit'.
    pub fn reporting(mut self) {
        let mut status = StatusValue::Exit;
        //TODO: spostare la open nello start e gestire errore
        let mut file = open_file(&self.filename).unwrap();
        let mut n_packets = 0;
        let mut write_titles = true;

        // Create the thread Timer

        // - Create a channel shared by the timer and the reporter to handle the close of the timer when the app goes in quit mode
        let (snd_timer, rcv_timer) = channel();

        // - Clone time interval to pass it to the timer
        let time_interval = self.time_interval.clone();
        // - Clone the writing status (shared by reporter and timer)
        let status_writing = self.status_writing.clone();
        // - Run the thread
        let timer_handle = thread::spawn(move || {

            // At each iteration wait at most 'time interval' seconds. If a packet is received before the timeout it means that the status got to 'Quit'
            // so also the timer need to return.
            // Otherwise 'time_interval' seconds passed so the timer sets the 'status_writing_value' to 'true' to notify the reporter to write the report.

            timer(rcv_timer, time_interval, status_writing);

        });


        loop {

            if !self.convs_summaries.is_empty() // If there are conversation to write
            {   // Get the lock and check if its time to update the report (status set to true)
                let mut status_writing_value = self.status_writing.lock().unwrap();

                if *status_writing_value == true {
                    println!("Scrivo su report!");
                    // Set to false the status value
                    *status_writing_value = false;
                    // Perform the update
                    write_summaries(&mut file, &self.convs_summaries, &self.initial_time, &self.time_interval, write_titles);
                    // Write titles only the first time.
                    if write_titles {
                        write_titles = false;
                    }
                    // Clear out the hash map
                    self.convs_summaries.clear();
                }
            }

            {  // Check the sniffing value getting the lock
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

                        // Conditional waiting until the status get back to "running" or is set to "exit"
                        status_sniffing_value = self.status_sniffing.cvar.wait_while(status_sniffing_value, |s| is_paused(&*s)).unwrap();

                        status = *status_sniffing_value;
                        // Here the status is either running or exit
                        assert_ne!(status, StatusValue::Paused);

                        if status == StatusValue::Exit{
                            continue;
                        }
                        // status running
                    }
                    StatusValue::Exit => {
                        if !self.convs_summaries.is_empty() {// Before exit update the report one last time and produces final report
                            println!("Scrivo su report!");
                            write_summaries(&mut file, &self.convs_summaries, &self.initial_time, &self.time_interval, false);
                        }


                        // Writes all conversations in final report
                        println!("Write final report");
                        let mut final_file = open_file(&self.final_filename).unwrap();
                        write_final_report(
                            &mut final_file,
                            &self.convs_final
                        );
                        // Alert the timer thread
                        println!("reporter notifies the timer and waits until it returns");
                        snd_timer.send(()).unwrap();
                        // Wait the conclusion of the timer handle
                        timer_handle.join().unwrap();

                        println!("Reporter exit, TOT Packets: {}", n_packets);

                        return;
                    }
                }
            }

            // Code reached only in running mode
            assert_eq!(status, StatusValue::Running);

            // Get a new packet_info from the channel (if its there)
            while let Ok(new_packet_info) = self.receiver_channel.try_recv(){
                // If the packet does not need to be filtered out add it in the hashmap
                if new_packet_info.get_printed() && check_filter(self.filter, new_packet_info.clone()){
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
/// Timer function. At each iteration it waits at most 'time interval' seconds. If a packet is received before the timeout it means that the status got to 'Quit'
/// so also the timer need to return.
/// Otherwise 'time_interval' seconds passed so the timer sets the 'status_writing_value' to 'true' to notify the reporter to write the report.
fn timer(rcv_timer: Receiver<()>, time_interval: usize, status_writing: Arc<Mutex<bool>>)
{
    loop {
         match rcv_timer.recv_timeout(Duration::from_secs(time_interval as u64)) {
            Ok(_) => {
                println!("Timer exit");
                break;
            },
            Err(err) =>
                if err == RecvTimeoutError::Timeout {
                    let mut status_writing_value = status_writing.lock().unwrap();
                    *status_writing_value = true;
                    println!("Time to update the report");
                }
        }
    }

}
/// It checks if the given packet_info needs to be filtered.
fn check_filter(filter: Filter, packet_info: PacketInfo) -> bool {
    if filter.get_ip_srg().is_some() &&
        packet_info.get_ip_sorgente().unwrap() != filter.get_ip_srg().unwrap() {
        return false;
    }
    if filter.get_ip_dest().is_some() &&
        packet_info.get_ip_destinazione().unwrap() != filter.get_ip_dest().unwrap() {
        return false;
    }
    if filter.get_prt_srg().is_some() &&
        packet_info.get_porta_sorgente() != filter.get_prt_srg().unwrap() {
        return false;
    }
    if filter.get_prt_dest().is_some() &&
        packet_info.get_porta_destinazione() != filter.get_prt_dest().unwrap() {
        return false;
    }
    true
}


/*
*  PRINT on FiLE FUNCTIONS
*
*/
/// Given a file name returns the handle of the opened file.
fn open_file(filename: &String) -> io::Result<File> {
    //TODO: GESTIRE ERRORE APERTURA FILE ???
    return File::options().write(true).truncate(true).create(true).open(filename);
}


/// It writes all the conversations contained in the HashMap in the file appending at the end of the file.
/// The conversations are organised in a table with rows: [time | ip_srg | prt_srg | ip_dest | prt_dest | protocol | tot_bytes | starting_time | ending_time | tot_packets ]
/// sorted by starting_time.
fn write_summaries(file: &mut File, convs_summaries: &HashMap<ConversationKey, ConversationStats>, time: &SystemTime, time_interval: &usize, write_titles: bool) {

    // Retrieves closest value of time interval since time elapsed
    let secs : u64 = time.elapsed().unwrap().as_secs()
        .div_euclid(*time_interval as u64)*(*time_interval as u64);
    let secs_str : String = secs.to_string();

    let style = Style::ascii();
    let column_dim = 15;
    let mut convs_printed = vec![];

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

        let conv = ConvTabled::new(
            secs_str.clone(),
            conv.0.get_ip_srg().to_string(),
            normalized_prt_src.to_string(),
            conv.0.get_ip_dest().to_string(),
            normalized_prt_dst.to_string(),
            conv.0.get_protocol().to_string(),
            conv.1.get_tot_bytes().to_string(),
            start_format,
            end_format,
            conv.1.get_tot_packets().to_string()
        );

        convs_printed.push(conv);
    }

    let mut table = Table::new(convs_printed);

    //per settare lo stile
    table = table.with(style.clone());

    //per settare la dim minima
    table = table.with(Modify::new(Rows::new(0..)).with(Width::increase(column_dim)));

    //scrivo l'header solo la prima volta
    if write_titles == false{
        table = table.with(Disable::Row(0..1));
    }

    //scrivo il report
    write!(file, "{}\n", table.to_string()).expect("Error during the writing of the report");

}
/// Write all the conversations sniffed by the analyser in the final report.
/// The conversations are organised in a table with rows: [time | ip_srg | prt_srg | ip_dest | prt_dest | protocol | tot_bytes | starting_time | ending_time | tot_packets ]
/// sorted by starting_time.
fn write_final_report(file: &mut File, convs_final: &HashMap<ConversationKey, ConversationStats>) {

    let style = Style::rounded();
    let column_dim = 15;
    let mut convs_printed = vec![];

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

            let conv = ConvTabled::new(
                "".to_string(),
                conv.0.get_ip_srg().to_string(),
                normalized_prt_src.to_string(),
                conv.0.get_ip_dest().to_string(),
                normalized_prt_dst.to_string(),
                conv.0.get_protocol().to_string(),
                conv.1.get_tot_bytes().to_string(),
                start_format,
                end_format,
                conv.1.get_tot_packets().to_string()
            );

            convs_printed.push(conv);
        }
        let mut table = Table::new(convs_printed);
        let dim = table.shape();
        //per settare lo stile
        table = table.with(style.clone());

        //per settare la dim minima
        table = table.with(Modify::new(Rows::new(0..)).with(Width::increase(column_dim)));


        table = table.with(Disable::Column(0..1));

        table = table.with(Modify::new(Columns::new(1..)).with(Border::default()
            .right('│').left('│')));

        table = table.with(Modify::new(tabled::object::Cell(0,0))
                               .with(Border::default()
                                   .top_left_corner('╭')
                                   .left('│')
                                   .bottom_left_corner('├')
                                   .bottom('─')));

        table = table.with(Modify::new(tabled::object::Cell(dim.0 -1,0))
            .with(Border::default()
                .bottom_left_corner('╰')));

        //scrivo il report
        write!(file, "{}\n", table.to_string()).expect("Error during the writing of the final report");

    }
}

/// Check if the status is 'Pause'
fn is_paused(state: &StatusValue) -> bool {
    return match state {
        StatusValue::Running => false,
        StatusValue::Paused => true,
        StatusValue::Exit => false
    };
}