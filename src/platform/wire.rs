//! Length-delimited, bounded local IPC. Never accept an executable path or a raw
//! core configuration from an unprivileged client.
use crate::{
    Result,
    config::{ConnectRequest, Mode},
    process::MAX_REQUEST,
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
pub const SOCKET: &str = "/var/run/io.eivro.tun.sock";
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Start {
        request: ConnectRequest,
        mode: Mode,
        authorization: Option<[u8; 32]>,
    },
    Stop {},
    Interfaces {},
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Hello {
        version: String,
    },
    Interfaces {
        interfaces: Vec<crate::network::Interface>,
    },
    Checking,
    Ready,
    Stopped,
    Denied,
    Failed {
        message: String,
    },
}
pub fn send<T: Serialize>(out: &mut impl Write, value: &T) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| "Не удалось подготовить команду помощнику.")?;
    if bytes.len() > MAX_REQUEST {
        return Err("Команда помощнику слишком велика.".into());
    }
    out.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| out.write_all(&bytes))
        .map_err(|_| "Канал помощника закрыт.".into())
}
pub fn receive<T: serde::de::DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut header = [0; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "Канал помощника закрыт.")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_REQUEST {
        return Err("Некорректный размер команды помощника.".into());
    }
    let mut bytes = vec![0; length];
    input
        .read_exact(&mut bytes)
        .map_err(|_| "Команда помощника прервана.")?;
    serde_json::from_slice(&bytes).map_err(|_| "Некорректная команда помощника.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn frames_do_not_consume_the_next_command() {
        let mut bytes = Vec::new();
        send(&mut bytes, &Request::Stop {}).unwrap();
        send(&mut bytes, &Request::Stop {}).unwrap();
        let mut input = Cursor::new(bytes);
        assert!(matches!(
            receive::<Request>(&mut input).unwrap(),
            Request::Stop {}
        ));
        assert!(matches!(
            receive::<Request>(&mut input).unwrap(),
            Request::Stop {}
        ));
        assert_eq!(input.position(), input.get_ref().len() as u64);
    }
    #[test]
    fn oversized_truncated_and_unknown_commands_fail_closed() {
        assert!(receive::<Request>(&mut Cursor::new(u32::MAX.to_be_bytes())).is_err());
        let mut truncated = 10_u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(b"{}");
        assert!(receive::<Request>(&mut Cursor::new(truncated)).is_err());
        for value in [
            serde_json::json!({"command":"execute","path":"/bin/sh"}),
            serde_json::json!({"command":"stop","unexpected":"private-input"}),
        ] {
            let mut bytes = Vec::new();
            send(&mut bytes, &value).unwrap();
            let error = receive::<Request>(&mut Cursor::new(bytes)).err().unwrap();
            assert!(!error.contains("private-input"));
        }
    }
}
