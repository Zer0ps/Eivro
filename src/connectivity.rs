//! A user-triggered connection check, never a timer or background ping.
use crate::Result;
use std::time::Duration;

pub fn check_url(port: u16, url: &str) -> Result<()> {
    let proxy = ureq::Proxy::new(format!("http://127.0.0.1:{port}"))
        .map_err(|_| "Неверный порт проверки.")?;
    let response = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_secs(6))
        .redirects(0)
        .build()
        .get(url)
        .set("User-Agent", "Velum connectivity check")
        .call()
        .map_err(|_| "Нет ответа через выбранный сервер.")?;
    if ![200, 204].contains(&response.status()) {
        return Err("Неожиданный ответ проверки соединения.".into());
    }
    Ok(())
}

pub fn check(port: u16) -> Result<()> {
    for url in [
        "https://example.com/",
        "https://www.gstatic.com/generate_204",
    ] {
        if check_url(port, url).is_ok() {
            return Ok(());
        }
    }
    Err(
        "Сервер не прошёл проверку HTTPS. Выберите другой сервер или проверьте сеть и другой VPN."
            .into(),
    )
}
