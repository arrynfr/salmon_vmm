#![feature(const_trait_impl)]
#![feature(effects)]
use std::{arch::asm, fs::File, os::fd::AsRawFd, process::exit, ptr::addr_of_mut};
use ioctl::*;

mod ioctl;

const KVMO: i32 = 0xAE;
const KVM_GET_API_VERSION: i32 = make_ioctl(IoctlDirection::None, 0x00, 0);
const KVM_GET_VCPU_MMAP: i32 = make_ioctl(IoctlDirection::None, 0x04, 0);
const KVM_CHECK_EXTENSION: i32 = make_ioctl(IoctlDirection::None, 0x03, 0);
const KVM_CREATE_VM: i32 = make_ioctl(IoctlDirection::None, 0x01, 0);
const KVM_CREATE_VCPU: i32 = make_ioctl(IoctlDirection::None, 0x41, 0);
const KVM_SET_USER_MEMORY_REGION: i32 = make_ioctl(IoctlDirection::Write, 0x46, std::mem::size_of::<KVMUserSpaceMemoryRegion>());
const KVM_SET_USER_MEMORY_REGION2: i32 = make_ioctl(IoctlDirection::Write, 0x49, std::mem::size_of::<KVMUserSpaceMemoryRegion>());
const KVM_RUN: i32 = make_ioctl(IoctlDirection::None, 0x80, 0);
const KVM_ARM_VCPU_INIT: i32 = make_ioctl(IoctlDirection::Write, 0xae, std::mem::size_of::<KVMVcpuInit>());
const KVM_ARM_PREFERRED_TARGET: i32 = make_ioctl(IoctlDirection::Read, 0xaf, std::mem::size_of::<KVMVcpuInit>());
const KVM_SET_ONE_REG: i32 = make_ioctl(IoctlDirection::Write, 0xac, std::mem::size_of::<KVMOneReg>());

struct KVMManager {
    kvm_device: File,
    vmid: i32,
    vcpu: i32,
    mmap_size: i32,
    ram: &'static mut [u8]
}

impl KVMManager {
    pub fn new() -> Self {
        let x = KVMManager {
            kvm_device: File::options().read(true).write(true).open("/dev/kvm").expect("/dev/kvm is not available"),
            vmid: -1,
            vcpu: -1,
            mmap_size: -1,
            ram: _mmap_4k(1, MemProt::PROT_RW, MemFlag::MAP_ANONSH, -1)
        };
        println!("Opened {:?}", x.kvm_device); //This is important it doesn't work otherwise???
        x
    }

    pub fn check_kvm_version(&self) -> Result<i32, i32> {
        let version = send_ioctl(self.kvm_device.as_raw_fd(), KVM_GET_API_VERSION);
        if version != 12 {
            return Err(version);
        }
        Ok(version)
    }
    
    pub fn check_kvm_ext(&self, cap: KVMCapabilities) -> Result<i32, i32> {
        let supported = send_ioctl_1(self.kvm_device.as_raw_fd(), KVM_CHECK_EXTENSION, cap as u64);
        if supported == 0 {
            return Err(supported);
        }
        Ok(supported)
    }
    
    pub fn create_vm(&mut self) -> Result<i32, i32> {
        let vmid = send_ioctl_1(self.kvm_device.as_raw_fd(), KVM_CREATE_VM, 0);
        self.vmid = vmid;
        if vmid <= 0 {
            return Err(vmid);
        }
        Ok(vmid)
    }

    pub fn set_memory_region(&self) -> Result<i32, i32> {
        let mut reg = KVMUserSpaceMemoryRegion {
            slot: 0,
            guest_phys_addr: 0x0,
            memory_size: self.ram.len() as u64,
            userspace_addr: self.ram.as_ptr() as u64,
            flags: 0
        };
        let res = send_ioctl_1(self.vmid, KVM_SET_USER_MEMORY_REGION, addr_of_mut!(reg) as u64);
        if res != 0 {
            return Err(res)
        }
        Ok(res)
    }

    pub fn create_vcpu(&mut self) -> Result<i32, i32> {
        let res = send_ioctl_1(self.vmid, KVM_CREATE_VCPU, 0);
        self.vcpu = res;
        if res <= 0 {
            return Err(res);
        }
        Ok(res)
    }

    pub fn get_vcpu_mem_map(&mut self) -> Result<i32, i32> {
        let res = send_ioctl(self.kvm_device.as_raw_fd(), KVM_GET_VCPU_MMAP); 
        self.mmap_size = res;
        if res <= 0 {
            return Err(res);
        }
        Ok(res)
    }
}

#[repr(C)]
struct KVMUserSpaceMemoryRegion {
    slot:               u32,
    flags:              u32,
    guest_phys_addr:    u64,
    memory_size:        u64,
    userspace_addr:     u64
}

#[repr(i32)]
enum KVMCapabilities {
    KvmCapIrqchip               = 0,
    KvmCapHlt                   = 1,
    KvmCapMmuShadowCacheControl = 2,
    KvmCapUserMemory            = 3,
    KvmCapSetTssAddr        = 4,
    KvmCapVapic               = 6,
    KvmCapExtCpuid           = 7,
    KvmCapClocksource         = 8,
    KvmCapNrVcpus            = 9,
    KvmCapNrMemslots         = 10,
    KvmCapPSCI              = 102
}

#[repr(u32)]
enum MemProt {
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_RW = 1 | 2,
}

#[repr(u32)]
enum MemFlag {
    MAP_SHARED = 0x1,
    MAP_ANONYMOUS = 0x20,
    MAP_ANONSH = (Self::MAP_ANONYMOUS as u32) | (Self::MAP_SHARED as u32)
}

fn _mmap_4k(num_pages: usize, prot: MemProt, flags: MemFlag, fd: i32) -> &'static mut [u8] {
    let mut ptr: *mut u8 = std::ptr::null_mut();
    unsafe {
        asm!("svc #0",
        inout("x0") 0_u64 => ptr,
        in("x1") 0x4000*num_pages,
        in("x2") prot as u32, //1 2 8 4
        in("x3") flags as u32,
        in("x4") fd,
        in("x5") 0,
        in("x8") 222);
    }
    unsafe {
        std::slice::from_raw_parts_mut(ptr, 0x4000*num_pages)
    }
}

#[repr(C)]
#[derive(Default, Debug)]
struct KVMRegs {
	user_pt_regs: UserPTRegs,
	sp_el1: u64,
	elr_el1: u64,
    spsr:[u64;5],
	fp_regs: UserFPSimdState,
}

#[repr(C)]
#[derive(Default, Debug)]
struct UserFPSimdState {
	vregs: [u128; 32],
	fpsr: u32,
	fpcr: u32,
	__reserved: [u32;2]
}

#[repr(C)]
#[derive(Default, Debug)]
struct UserPTRegs {
	regs: [u64; 31],
	sp: u64,
	pc: u64,
	pstate: u64
}

const KVM_ARM_TARGET_GENERIC_V8: u32 = 5;

#[repr(C)]
#[derive(Default, Debug)]
struct KVMVcpuInit {
	target: u32,
	features: [u32; 7]
}

#[repr(C)]
#[derive(Default, Debug)]
struct KVMRun {
	/* in */
    request_interrupt_window: u8,
	immediate_exit: u8,
	padding1: [u8;6],

	/* out */
	exit_reason: u32,
	ready_for_interrupt_injection: u8,
	if_flag: u8,
	flags: u16
}

#[repr(C)]
#[derive(Default, Debug)]
struct KVMOneReg {
	id: u64,
	addr: u64
}

fn main() {
    let mut kvm_manager = KVMManager::new();
    kvm_manager.check_kvm_version().expect("Unsupported KVM version");
    kvm_manager.check_kvm_ext(KVMCapabilities::KvmCapUserMemory).expect("We don't support user memory region");
    kvm_manager.check_kvm_ext(KVMCapabilities::KvmCapPSCI).expect("We don't support PSCI");
    let slots = kvm_manager.check_kvm_ext(KVMCapabilities::KvmCapNrMemslots).unwrap();
    println!("Max slots: {slots:}");
    let vmid = kvm_manager.create_vm().expect("Couldn't create VM");
    println!("Created vm with VMID: {}", vmid);
    for x in (0..kvm_manager.ram.len()).step_by(16) {
        /* 0000000000000000 <_start>:
           0:   58000040        ldr     x0, 8 <_start+0x8>
           4:   d4000002        hvc     #0x0
           8:   84000008        .word   0x84000008
           c:   00000000        .word   0x00000000 */
        kvm_manager.ram[x+15] = 0x00;
        kvm_manager.ram[x+14] = 0x00;
        kvm_manager.ram[x+13] = 0x00;
        kvm_manager.ram[x+12] = 0x00;
        kvm_manager.ram[x+11] = 0x84;
        kvm_manager.ram[x+10] = 0x00;
        kvm_manager.ram[x+9] = 0x00;
        kvm_manager.ram[x+8] = 0x08;
        kvm_manager.ram[x+7] = 0xd4;
        kvm_manager.ram[x+6] = 0x00;
        kvm_manager.ram[x+5] = 0x00;
        kvm_manager.ram[x+4] = 0x02;
        kvm_manager.ram[x+3] = 0x58;
        kvm_manager.ram[x+2] = 0x00;
        kvm_manager.ram[x+1] = 0x00;
        kvm_manager.ram[x+0] = 0x40;
    }

    kvm_manager.set_memory_region().expect("Cannot set memory region");
    let vcpu = kvm_manager.create_vcpu().expect("Cannot create vcpu");
    println!("Created vcpu: {vcpu}");
    let mem_map = kvm_manager.get_vcpu_mem_map().expect("Couldn't get vcpu mem map");
    println!("Got size: {mem_map:#x?}");
    let run_mem = _mmap_4k((mem_map/0x4000) as usize, MemProt::PROT_RW, MemFlag::MAP_SHARED, kvm_manager.vcpu);
    let run: &mut KVMRun = unsafe { (run_mem.as_ptr() as *mut KVMRun).as_mut().unwrap() };
    let mut test = KVMVcpuInit::default();
    test.target = KVM_ARM_TARGET_GENERIC_V8;
    test.features[0] |= 1 << 2;
    send_ioctl_1(kvm_manager.vcpu, KVM_ARM_VCPU_INIT, addr_of_mut!(test) as u64);
    
    let mut addr = 0_u64;
    let mut k = KVMOneReg {
        id:  0x6000000000000000_u64 | 0x0030000000000000_u64 | (0x0010 << 16) | 64,
        addr: addr_of_mut!(addr) as u64
    };

    let x = send_ioctl_1(kvm_manager.vcpu, KVM_SET_ONE_REG, addr_of_mut!(k) as u64);
    println!("{:x}", x);

    println!("Running VM...");
    loop {
        send_ioctl_1(kvm_manager.vcpu, KVM_RUN, 0);
        match run.exit_reason {
            0 => {},
            _ => {
                println!("Exitting with: {}", run.exit_reason);
                exit(run.exit_reason as i32)
            }
        }
    }
}
