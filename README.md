BPF JIT
=======

BPF to amd64 JIT compiler for rust extracted from FreeBSD 10 tree.

Example usage
-------------

```rust
extern crate bpfjit;
extern crate pcap;
use std::mem;

fn main() {
    let pcap = pcap::Capture::dead(pcap::Linktype(12 /* raw ip */)).unwrap();
    let bpf_prog = pcap.compile("tcp and dst port 80").unwrap();
    let insns = bpf_prog.get_instructions();
    let filter = bpfjit::BpfJitFilter::compile(unsafe {
        mem::transmute(insns)
    }).unwrap();
    let data = [1,2,3,4];
    if filter.matched(&data[..]) {
        // ...
    }
}
```
