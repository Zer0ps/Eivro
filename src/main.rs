mod emoji;
#[cfg_attr(target_os = "macos", path = "platform/macos/instance.rs")]
mod instance;
mod ui;

fn main() -> eframe::Result {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("Eivro {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() == 2 && args[1] == "--resolve-system" {
        std::process::exit(
            if eivro::privacy::harden().is_ok() && eivro::resolver::worker().is_ok() {
                0
            } else {
                1
            },
        );
    }
    if args.len() == 2 && args[1] == "--recover-proxy" {
        if eivro::privacy::harden().is_err() {
            std::process::exit(1);
        }
        std::process::exit(if eivro::system_proxy::recover_stale().is_ok() {
            0
        } else {
            1
        });
    }
    if args.len() == 3 && ["--proxy-guard", "--check-connection"].contains(&args[1].as_str()) {
        if eivro::privacy::harden().is_err() {
            std::process::exit(1);
        }
        let Ok(port) = args[2].parse::<u16>() else {
            std::process::exit(1);
        };
        if port < 1024 {
            std::process::exit(1);
        }
        if args[1] == "--check-connection" {
            std::process::exit(if eivro::connectivity::check(port).is_ok() {
                0
            } else {
                1
            });
        }
        match eivro::system_proxy::guard(port) {
            Ok(true) => std::process::exit(0),
            Ok(false) => std::process::exit(2),
            Err(error) => {
                println!("ERROR: {error}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(target_os = "macos")]
    if args.len() == 2 && args[1] == "--authorize" {
        return eivro::platform::macos::authorization::worker()
            .map_err(|e| eframe::Error::AppCreation(Box::new(std::io::Error::other(e))));
    }
    #[cfg(not(feature = "qa"))]
    if eivro::privacy::harden().is_err() || eivro::privacy::silence_stdio().is_err() {
        std::process::exit(1);
    }
    let scope = eivro::storage::instance_scope()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "default".into());
    let instance =
        match instance::Instance::acquire(&scope, !args.iter().any(|s| s == "--background")) {
            Ok(Some(instance)) => instance,
            Ok(None) => return Ok(()),
            Err(_) => {
                return Err(eframe::Error::AppCreation(Box::new(std::io::Error::other(
                    "Не удалось открыть канал Eivro.",
                ))));
            }
        };
    // Winit's native Wayland backend cannot hide or reactivate a window.
    // XWayland provides both operations needed by a persistent tray client.
    #[cfg(target_os = "linux")]
    let window_hiding = std::env::var_os("DISPLAY").is_some_and(|s| !s.is_empty());
    #[cfg(target_os = "macos")]
    let window_hiding = true;
    let initial_size = [960.0, 760.0];
    #[cfg(feature = "qa")]
    let initial_size = match std::env::var("EIVRO_QA_SIZE").as_deref() {
        Ok("compact") => [820.0, 640.0],
        Ok("large") => [1280.0, 900.0],
        Ok("wide") => [1800.0, 1100.0],
        _ => initial_size,
    };
    // Performance tests may use an isolated XDG_CONFIG_HOME; normal use follows XDG.
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Eivro")
            .with_app_id("io.eivro.Client")
            .with_inner_size(initial_size)
            .with_min_inner_size([820.0, 640.0]),
        renderer: eframe::Renderer::Glow,
        vsync: true,
        #[cfg(target_os = "linux")]
        event_loop_builder: Some(Box::new(move |builder| {
            if window_hiding {
                use winit::platform::x11::EventLoopBuilderExtX11;
                builder.with_x11();
            }
        })),
        ..Default::default()
    };
    eframe::run_native(
        "Eivro",
        options,
        Box::new(move |cc| Ok(Box::new(ui::App::new(cc, instance, window_hiding)))),
    )
}
