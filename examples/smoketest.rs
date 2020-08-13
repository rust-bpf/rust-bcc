use bcc::table::Entry;
use bcc::BPF;

fn main() {
    println!("smoketest: empty table");
    let bpf = BPF::new("BPF_HASH(start, u32);").unwrap();
    let table = bpf.table("start");
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 0);

    println!("smoketest: sized histogram");
    let bpf = BPF::new("BPF_HISTOGRAM(dist, int, 256);").unwrap();
    let table = bpf.table("dist");
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 256);

    println!("smoketest: hash insert and delete");
    let bpf = BPF::new("BPF_HASH(dist);").unwrap();
    let mut table = bpf.table("dist");
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 0);
    assert!(table.delete_all().is_ok());
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 0);
    assert!(table
        .set(
            &mut [0, 0, 0, 0, 0, 0, 0, 1],
            &mut [0, 0, 0, 0, 0, 0, 0, 42]
        )
        .is_ok());
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries.get(0).unwrap().value, [0, 0, 0, 0, 0, 0, 0, 42]);
    assert!(table.delete_all().is_ok());
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 0);

    println!("smoketest: array");
    let bpf = BPF::new("BPF_ARRAY(dist, u64, 64);").unwrap();
    let mut table = bpf.table("dist");
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 64);
    assert!(table
        .set(&mut [0, 0, 0, 0], &mut [0, 0, 0, 0, 0, 0, 0, 42])
        .is_ok());
    assert!(table
        .set(&mut [1, 0, 0, 0], &mut [0, 0, 0, 0, 0, 0, 13, 37])
        .is_ok());
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.get(1).unwrap().value, [0, 0, 0, 0, 0, 0, 13, 37]);
    assert_eq!(entries.get(0).unwrap().value, [0, 0, 0, 0, 0, 0, 0, 42]);

    println!("smoketest passed");
}
