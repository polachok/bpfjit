extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("src/bpf_jit_machdep.c")
        .include("src")
        .define("__FBSDID(__x)", Some(""))
        .compile("libbpfjit.a");
}
