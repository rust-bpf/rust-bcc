/*
 * Regression test for a segfault occuring in bcc when bpf_load_prog fails and attempts
 * to populate a non-null buffer with the error message.
 */
#[cfg(test)]
mod tests {

    extern crate bcc;

    use bcc::core::BPF;

    #[test]
    fn error_handling() {
        let code = include_str!("error.c");
        // compile the above BPF code!
        let mut module = BPF::new(code).unwrap();
        match module.load_kprobe("trace_return") {
            Ok(_) => {
                eprintln!("expected error during program load");
                std::process::exit(1);
            }
            Err(_) => {}
        };
    }
}
