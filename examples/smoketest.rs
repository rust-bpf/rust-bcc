use bcc::perf_event::{Event, SoftwareEvent};
use bcc::table::Entry;
use bcc::{BPFBuilder, BpfProgType, PerfEvent, XDPMode, BPF, XDP};

fn main() {
    println!("smoketest: empty table");
    let bpf = BPF::new("BPF_HASH(start, u32);").unwrap();
    let table = bpf.table("start").unwrap();
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 0);

    println!("smoketest: sized histogram");
    let bpf = BPF::new("BPF_HISTOGRAM(dist, int, 256);").unwrap();
    let table = bpf.table("dist").unwrap();
    let entries: Vec<Entry> = table.iter().collect();
    assert_eq!(entries.len(), 256);

    println!("smoketest: hash insert and delete");
    let bpf = BPF::new("BPF_HASH(dist);").unwrap();
    let mut table = bpf.table("dist").unwrap();
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

    println!("smoketest: invalid hash usage");
    assert!(bpf.table("invalid\0_table_name").is_err());
    let mut table = bpf.table("does_not_exist").unwrap();
    assert!(table.get(&mut [0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    assert!(table.delete(&mut [0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    assert!(table
        .set(
            &mut [0, 0, 0, 0, 0, 0, 0, 1],
            &mut [0, 0, 0, 0, 0, 0, 0, 42]
        )
        .is_err());

    println!("smoketest: array");
    let bpf = BPF::new("BPF_ARRAY(dist, u64, 64);").unwrap();
    let mut table = bpf.table("dist").unwrap();
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

    println!("smoketest: cflags");
    assert!(BPFBuilder::new("int main() { return RETURN_CODE; }")
        .unwrap()
        .cflags(&["-DRETURN_CODE=0", "-DUNUSED_DEFINE=1"])
        .unwrap()
        .build()
        .is_ok());

    println!("smoketest: debug level");
    assert!(BPFBuilder::new("")
        .unwrap()
        .debug(Default::default())
        .build()
        .is_ok());

    println!("smoketest: tail calls");
    run_tail_calls();

    println!("smoketest: xdp forwarding");
    run_xdp_forwarding();

    println!("smoketest passed");
}

#[cfg(any(
    feature = "v0_6_0",
    feature = "v0_6_1",
    feature = "v0_7_0",
    feature = "v0_8_0",
))]
fn run_tail_calls() {
    let mut bpf = BPFBuilder::new(
        "#include <uapi/linux/bpf_perf_event.h>
        BPF_PROG_ARRAY(programs, 1);

        int my_func(struct bpf_perf_event_data *ctx) {
            return 0;
        }
        int on_event(struct bpf_perf_event_data *ctx){
            programs.call(ctx, 0);
            return 0;
        }",
    )
    .unwrap()
    .build()
    .unwrap();

    PerfEvent::new()
        .handler("on_event")
        .event(Event::Software(SoftwareEvent::CpuClock))
        .sample_frequency(Some(99))
        .attach(&mut bpf)
        .unwrap();

    let mut table = bpf.table("programs").unwrap();
    let mut index = 0_u32.to_ne_bytes();

    assert!(bpf.load_func("my_func", BpfProgType::PerfEvent).is_err())
}

#[cfg(any(
    feature = "v0_9_0",
    feature = "v0_10_0",
    feature = "v0_11_0",
    feature = "v0_12_0",
    feature = "v0_13_0",
    feature = "v0_14_0",
    feature = "v0_15_0",
    feature = "v0_16_0",
    feature = "v0_17_0",
    feature = "v0_18_0",
    feature = "v0_19_0",
    not(feature = "specific"),
))]
fn run_tail_calls() {
    let mut bpf = BPFBuilder::new(
        "#include <uapi/linux/bpf_perf_event.h>
        BPF_PROG_ARRAY(programs, 1);

        int my_func(struct bpf_perf_event_data *ctx) {
            return 0;
        }
        int on_event(struct bpf_perf_event_data *ctx){
            programs.call(ctx, 0);
            return 0;
        }",
    )
    .unwrap()
    .build()
    .unwrap();

    PerfEvent::new()
        .handler("on_event")
        .event(Event::Software(SoftwareEvent::CpuClock))
        .sample_frequency(Some(99))
        .attach(&mut bpf)
        .unwrap();

    let mut table = bpf.table("programs").unwrap();
    let mut index = 0_u32.to_ne_bytes();
    let fd = bpf.load_func("my_func", BpfProgType::PerfEvent).unwrap();
    let fd2 = bpf.load_func("my_func", BpfProgType::PerfEvent).unwrap();
    assert_eq!(
        fd, fd2,
        "loading the same function more than once should return the same fd"
    );
    table.set(&mut index, &mut fd.to_ne_bytes()).unwrap();
    assert!(bpf
        .load_func("non_existent_func", BpfProgType::PerfEvent)
        .is_err());
}

fn run_xdp_forwarding() {
    let mut bpf = BPFBuilder::new(
        "#include<uapi/linux/bpf.h>
        int my_func(struct xdp_md *ctx) {
            return XDP_PASS;
        }",
    )
    .unwrap()
    .build()
    .unwrap();

    XDP::new()
        .device("lo")
        .handler("my_func")
        .mode(XDPMode::XDP_FLAGS_SKB_MODE)
        .attach(&mut bpf)
        .expect("failed to attach XDP program to device");
}
