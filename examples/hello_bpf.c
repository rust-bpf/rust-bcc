int some_func(void *ctx){
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}