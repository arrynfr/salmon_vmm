use std::arch::asm;

const IOCTL_SYSCALL: u64 = 29;

#[repr(i8)]
#[derive(PartialEq, Clone, Copy)]
pub enum IoctlDirection {
    None        = 0,
    Write       = 1 << 0,
    Read        = 1 << 1,
    ReadWrite   = 0b11
}

pub const fn make_ioctl(direction: IoctlDirection, number: i32, size: usize) -> i32 {
    if direction as i8 == IoctlDirection::None as i8 {
        assert!(size == 0, "Direction is none but size != 0!");
    }

    let ioctl_type = 0xae;
    number | ioctl_type << 8 | (size as i32) << 16 | (direction as i32) << 30
}

pub fn send_ioctl(fd: i32, ioctl: i32) -> i32 {
    let result: i32;
    unsafe {
        asm!("svc #0",
        inout("x0") fd => result,
        in("x1") ioctl,
        in("x8") IOCTL_SYSCALL
        );
    }
    result
}

#[no_mangle]
pub fn send_ioctl_1(fd: i32, ioctl: i32, arg1: u64) -> i32 {
    let result: i32;
    unsafe {
        asm!("svc #0",
        inout("x0") fd => result,
        in("x1") ioctl,
        in("x2") arg1,
        in("x8") IOCTL_SYSCALL
        );
    }
    result
}