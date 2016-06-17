extern crate libc;

#[repr(C)]
pub struct bpf_insn {
	code: libc::c_ushort,
	jt: libc::c_uchar,
	jf: libc::c_uchar,
	k: libc::uint32_t,
}

#[allow(non_camel_case_types)]
type bpf_filter_func = extern "C" fn(*const libc::c_uchar, libc::c_uint, libc::c_uint) -> libc::c_uint;
extern "C" {
    fn bpf_jit_compile(filter: *const bpf_insn, nins: libc::c_uint, size: *mut libc::size_t) -> Option<bpf_filter_func>;
}

pub struct BpfJitFilter {
    func: bpf_filter_func,
    size: usize,
}

impl BpfJitFilter {
    /// Compiles classic BPF instructions to amd64 instructions
    pub fn compile(instructions: &[bpf_insn]) -> Option<BpfJitFilter> {
        let mut size: libc::size_t = 0;
        match unsafe { bpf_jit_compile(instructions.as_ptr(), instructions.len() as u32, &mut size) } {
            Some(f) => Some(BpfJitFilter {
                func: f,
                size: size,
            }),
            None => None,
        }
    }
    
    /// Applies filter. Returns true on match, false otherwise
    pub fn matched(&self, buf: &[u8]) -> bool {
        (self.func)(buf.as_ptr(), buf.len() as u32, buf.len() as u32) > 0
    }
}

impl Drop for BpfJitFilter {
    fn drop(&mut self) {
        use std::mem;
        unsafe {
            let ptr = mem::transmute(self.func);
            libc::munmap(ptr, self.size);
        }
    }
}

impl Clone for BpfJitFilter {
    fn clone(&self) -> Self {
        use std::ptr;
        use std::mem;
        let code = unsafe {
            let mem = libc::mmap(ptr::null_mut(), self.size, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0);
            ptr::copy_nonoverlapping(mem::transmute(self.func), mem, self.size);
            libc::mprotect(mem, self.size, libc::PROT_READ | libc::PROT_EXEC);
            mem
        };
        BpfJitFilter {
            func: unsafe { mem::transmute(code) },
            size: self.size,
        }
    }
}

#[test]
fn simple_match() {
    /* tcp and host 185.50.25.2 */
    let filter = [
		bpf_insn { code: 0x28, jt: 0, jf: 0, k: 0x0000000c },
		bpf_insn { code: 0x15, jt: 8, jf: 0, k: 0x000086dd },
		bpf_insn { code: 0x15, jt: 0, jf: 7, k: 0x00000800 },
		bpf_insn { code: 0x30, jt: 0, jf: 0, k: 0x00000017 },
		bpf_insn { code: 0x15, jt: 0, jf: 5, k: 0x00000006 },
		bpf_insn { code: 0x20, jt: 0, jf: 0, k: 0x0000001a },
		bpf_insn { code: 0x15, jt: 2, jf: 0, k: 0xb9321902 },
		bpf_insn { code: 0x20, jt: 0, jf: 0, k: 0x0000001e },
		bpf_insn { code: 0x15, jt: 0, jf: 1, k: 0xb9321902 },
		bpf_insn { code: 0x6, jt: 0, jf: 0, k: 0x0000ffff },
		bpf_insn { code: 0x6, jt: 0, jf: 0, k: 0x00000000 },
    ];

    let packet = [
        0x68, 0x05, 0xca, 0x21, 0x58, 0x86,
       	0x94, 0xde, 0x80, 0x69, 0xbb, 0xe6,
       	0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x78, 0x85, 0x40, 0x00,
       	0x40, 0x06, 0x13, 0xb6, 0x0a, 0x64,
       	0xd1, 0xe8, 0xb9, 0x32,
        0x19, 0x02, 0x83, 0xbf, 0x00, 0x16,
       	0x8d, 0x70, 0xa5, 0x97, 0x00, 0x00,
       	0x00, 0x00, 0xa0, 0x02,
        0x72, 0x10, 0x74, 0x3e, 0x00, 0x00, 
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
       	0x08, 0x0a, 0x1f, 0x40,
        0xdd, 0x12, 0x00, 0x00, 0x00, 0x00,
       	0x01, 0x03, 0x03, 0x07, 
    ];

    let jit_filter = BpfJitFilter::compile(&filter).unwrap();
    assert!(jit_filter.matched(&packet) == true);
}

#[test]
fn simple_match_cloned() {
    /* tcp and host 185.50.25.2 */
    let filter = [
		bpf_insn { code: 0x28, jt: 0, jf: 0, k: 0x0000000c },
		bpf_insn { code: 0x15, jt: 8, jf: 0, k: 0x000086dd },
		bpf_insn { code: 0x15, jt: 0, jf: 7, k: 0x00000800 },
		bpf_insn { code: 0x30, jt: 0, jf: 0, k: 0x00000017 },
		bpf_insn { code: 0x15, jt: 0, jf: 5, k: 0x00000006 },
		bpf_insn { code: 0x20, jt: 0, jf: 0, k: 0x0000001a },
		bpf_insn { code: 0x15, jt: 2, jf: 0, k: 0xb9321902 },
		bpf_insn { code: 0x20, jt: 0, jf: 0, k: 0x0000001e },
		bpf_insn { code: 0x15, jt: 0, jf: 1, k: 0xb9321902 },
		bpf_insn { code: 0x6, jt: 0, jf: 0, k: 0x0000ffff },
		bpf_insn { code: 0x6, jt: 0, jf: 0, k: 0x00000000 },
    ];

    let packet = [
        0x68, 0x05, 0xca, 0x21, 0x58, 0x86,
       	0x94, 0xde, 0x80, 0x69, 0xbb, 0xe6,
       	0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x78, 0x85, 0x40, 0x00,
       	0x40, 0x06, 0x13, 0xb6, 0x0a, 0x64,
       	0xd1, 0xe8, 0xb9, 0x32,
        0x19, 0x02, 0x83, 0xbf, 0x00, 0x16,
       	0x8d, 0x70, 0xa5, 0x97, 0x00, 0x00,
       	0x00, 0x00, 0xa0, 0x02,
        0x72, 0x10, 0x74, 0x3e, 0x00, 0x00, 
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
       	0x08, 0x0a, 0x1f, 0x40,
        0xdd, 0x12, 0x00, 0x00, 0x00, 0x00,
       	0x01, 0x03, 0x03, 0x07, 
    ];

    let jit_filter = BpfJitFilter::compile(&filter).unwrap();
    let cloned_filter = jit_filter.clone();
    assert!(cloned_filter.matched(&packet) == true);
}
