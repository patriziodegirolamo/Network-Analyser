use pcap::{Device, Capture, Direction};

fn print_list_devices(){
    Device::list().unwrap().into_iter().for_each(|dev| println!("Device {:?}", dev.desc.unwrap()));
}
fn main() {

    /**
    PROBLEMI:
    1) settando una qualsiasi interfaccia come promiscua, dovrebbe poter intercettare il traffico
    passante su tutte le altre interfacce. il problema è che non lo cattura.

    2) il metodo timeout(..) dovrebbe interrompere la lettura del traffico dopo TOT millisecondi.
    anche questo non funziona

    3)NON riesco a trovare da nessuna parte le informazioni sui pacchetti: IP, porte ecc.
    */
    let nmilli = 3000;

    print_list_devices();

    //provo a leggere il traffico dall'interfaccia principale
    let main_dv = Device::lookup().unwrap().unwrap();
    println!("\n\n---- {}", main_dv.desc.clone().unwrap());

    let mut main_capture = Capture::from_device(main_dv).unwrap()
        .promisc(true).timeout(nmilli)
        .open().unwrap();
    /*
    while let Ok(packet) = main_capture.next_packet() {
        println!("ok");
    }
    */

    //ora leggo il traffico da quella funzionante, nel mio caso la "Intel(R) Dual Band Wireless-AC 8265"
    //la 3 nella lista
    let selected = 3;

    let list = Device::list().expect("ERROR");
    let chosen_dev = list.get(selected).unwrap();
    println!("addresses: {:?}", chosen_dev.addresses);

    let mut chosen_capture = Capture::from_device(chosen_dev.clone()).unwrap()
        //.promisc(true)
        //.timeout(nmilli)
        .open()
        .unwrap();

    println!("\n\n---- {}", chosen_dev.desc.clone().unwrap());

    for i in 0..10{
        let packet = chosen_capture.next_packet().ok();
        println!("{:?}", packet);
    }


    /*
    while let Ok(packet) = chosen_capture.next_packet() {
        println!("{:?}", packet);
    }
     */


    println!("{:?}",chosen_capture.stats().unwrap());





}