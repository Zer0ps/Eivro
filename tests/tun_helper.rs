#![cfg(target_os = "linux")]
//! Real core supervision over a pipe; Mode::Local never creates TUN or changes DNS.
use eivro::{
    config::{ConnectRequest, Mode},
    process,
    tun::{self, CommandMessage},
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
fn request() -> ConnectRequest {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    ConnectRequest {
        connections: vec![],
        uri: "ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:1".into(),
        bypass: vec![],
        port,
        bridge_port: None,
        probe_port: None,
        policies: vec![],
        kill_switch: false,
    }
}
fn send(stream: &mut UnixStream, message: CommandMessage) {
    let mut data = serde_json::to_vec(&message).unwrap();
    data.push(b'\n');
    stream.write_all(&data).unwrap();
}
fn line(reader: &mut BufReader<UnixStream>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line
}
#[test]
fn one_helper_handles_reconnect_core_crash_and_gui_eof() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(8)))
        .unwrap();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let pid = Arc::new(AtomicU32::new(0));
    let child_pid = pid.clone();
    let worker = std::thread::spawn(move || {
        tun::serve(server.try_clone().unwrap(), server, |req| {
            let child = process::spawn_core(&process::core_path()?, req, Mode::Local)?;
            child_pid.store(child.id(), Ordering::SeqCst);
            Ok(child)
        })
    });
    let first = request();
    let first_port = first.port;
    send(&mut client, CommandMessage::Start { request: first });
    assert_eq!(line(&mut reader), "READY\n");
    let pid1 = pid.load(Ordering::SeqCst);
    send(
        &mut client,
        CommandMessage::Stop {
            preserve_protection: false,
        },
    );
    assert_eq!(line(&mut reader), "STOPPED\n");
    assert!(TcpListener::bind(("127.0.0.1", first_port)).is_ok());
    let second = request();
    send(&mut client, CommandMessage::Start { request: second });
    assert_eq!(line(&mut reader), "READY\n");
    let pid2 = pid.load(Ordering::SeqCst);
    assert_ne!(pid1, pid2);
    unsafe {
        libc::kill(pid2 as i32, libc::SIGKILL);
    };
    assert_eq!(line(&mut reader), "FAILED\n");
    let third = request();
    let third_port = third.port;
    send(&mut client, CommandMessage::Start { request: third });
    assert_eq!(line(&mut reader), "READY\n");
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(worker.join().unwrap().is_ok());
    assert!(TcpListener::bind(("127.0.0.1", third_port)).is_ok());
}
#[test]
fn malformed_protocol_stops_the_owned_core() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(8)))
        .unwrap();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let worker = std::thread::spawn(move || {
        tun::serve(server.try_clone().unwrap(), server, |req| {
            process::spawn_core(&process::core_path()?, req, Mode::Local)
        })
    });
    let req = request();
    let port = req.port;
    send(&mut client, CommandMessage::Start { request: req });
    assert_eq!(line(&mut reader), "READY\n");
    client
        .write_all(b"{\"command\":\"shell\",\"path\":\"/bin/sh\"}\n")
        .unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
}
