/*
 * Regression test for a segfault occuring in bcc when bpf_load_prog fails and attempts
 * to populate a non-null buffer with the error message.
 */
#[cfg(test)]
mod tests {

    extern crate bcc;

    use bcc::{Kprobe, BPF};

    #[test]
    fn error_handling() {
        let code = include_str!("error.c");
        // compile the above BPF code!
        let mut module = BPF::new(code).unwrap();
        if Kprobe::new()
            .name("trace_return")
            .function("do_sys_open")
            .attach(&mut module)
            .is_ok()
        {
            eprintln!("expected error during program load");
            std::process::exit(1);
        }
    }
}
