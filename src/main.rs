// The `FROM scratch` image is static musl, whose malloc takes one global lock, which the throughput benchmark measured on amd64.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashMap;
use std::io::Write;
use std::process::ExitCode;

use mock_server::cli::{self, Action, After};
use mock_server::Server;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("healthcheck") {
        return healthcheck();
    }
    // `mock-server migrate`: ours, outside the picocli tree (the oracle answers it with a usage error)
    if args.first().map(String::as_str) == Some("migrate") {
        let env: Vec<(String, String)> = std::env::vars().collect();
        let outcome = mock_server::migrate::run(&args[1..], &env);
        print!("{}", outcome.out);
        eprint!("{}", outcome.err);
        return ExitCode::from(outcome.code);
    }
    let env: HashMap<String, String> = std::env::vars().collect();
    // `Main`: `--print-config` anywhere on the command line prints the effective configuration and exits, before any
    // other parsing (so it needs no port), like `--help`/`--version`.
    if args.iter().any(|a| a == "--print-config") {
        print!("{}", mock_server::Config::for_print_config(&args, env).effective_configuration_text());
        return ExitCode::SUCCESS;
    }
    // the console: `tracing` events written to stdout from a thread of their own, off the request workers so a
    // synchronous console write no longer limits throughput, installed before anything can log (an import failure,
    // `Main`'s startup lines)
    cli::install_console();
    let planned = cli::plan(&args, &env);
    emit(&planned.out, &planned.err);
    match planned.action {
        Action::Exit(code) => ExitCode::from(code),
        Action::Import(import) => {
            let (out, err, code) = cli::run_import(&import);
            emit(&out, &err);
            ExitCode::from(code)
        }
        Action::Lint(lint) => {
            let (out, err, code) = cli::run_lint(&lint);
            emit(&out, &err);
            ExitCode::from(code)
        }
        Action::Start(start) => run_server(*start, env),
    }
}

/// Writes what `cli::plan` decided to print: `out` to stdout, `err` to stderr.
fn emit(out: &str, err: &str) {
    // after the console lines queued before it (the writer thread prints them, see `run_server`)
    cli::flush_console();
    print!("{out}");
    let _ = std::io::stdout().flush();
    eprint!("{err}");
    let _ = std::io::stderr().flush();
}

fn run_server(start: cli::Start, env: HashMap<String, String>) -> ExitCode {
    let cli::Start { config, after, dump } = start;
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    // an explicit `nioEventLoopThreadCount` is the worker count; unset, tokio's default (available cores)
    if let Some(workers) = cli::worker_threads(&config) {
        builder.worker_threads(workers);
    }
    let runtime = builder.enable_all().build().expect("tokio runtime");
    let code = runtime.block_on(async move {
        #[cfg(unix)]
        flush_on_terminate();
        cli::startup_notices(&config);
        cli::jvm_only_notice(&config);
        if let Some(dump) = &dump {
            cli::main_line(&config, "INFO", "INFO", dump);
        }
        let logger_config = config.clone();
        // `Main` catches the `IllegalArgumentException` of an HTTP(S) proxy together with a SOCKS proxy: usage, exit code 0.
        if cli::proxy_conflict(&config) {
            emit(&cli::startup_failure_usage(&env), "");
            return ExitCode::SUCCESS;
        }
        // `LifeCycle` starts the extensions before `createServerBootstrap`'s refusals below; an `ExtensionException`
        // takes `Main.logStartupFailure`'s generic branch and exit code 1.
        if let Some(shown) = cli::extension_refusal(&config) {
            cli::main_line(&config, &config.log_level(), "ERROR", &format!("exception while starting:{{}} \n{shown}"));
            if cli::system_out_disabled(&config) {
                eprintln!("java.lang.RuntimeException: exception while starting: {}", shown.split_once(": ").map_or(shown.as_str(), |(_, message)| message));
            }
            return ExitCode::from(1);
        }
        // `ControlPlaneMutualTlsConfigurationException` is an `IllegalArgumentException`: `MockServer` stops what its
        // `LifeCycle` built (`stopped for ports: []`), and `RunCommand` takes it for a usage error, shows the usage
        // without the message and exits 0. `DataPlaneMutualTlsConfigurationException` (9.1.0) is one too, checked next.
        if cli::unusable_control_plane_mtls(&config) || cli::unusable_control_plane_basic(&config) || cli::unusable_data_plane_mtls(&config) {
            cli::main_line(&config, &config.log_level(), "INFO", "stopped for ports: []");
            emit(&cli::startup_failure_usage(&env), "");
            return ExitCode::SUCCESS;
        }
        let server = match Server::start(config).await {
            Ok(server) => server,
            Err(e) if e.get_ref().is_some_and(|inner| inner.is::<mock_server::UdpStartFailure>()) => {
                let failure = e.get_ref().and_then(|inner| inner.downcast_ref::<mock_server::UdpStartFailure>()).expect("checked above");
                cli::udp_start_failure(&logger_config, failure);
                return ExitCode::from(1);
            }
            Err(e) => {
                // `MockServer.createServerBootstrap` logs a port it cannot bind before rethrowing (portless: no port is
                // bound yet); then `RunCommand` logs the exception (`Main.logStartupFailure`) and exits 1, without the
                // usage: only an `IllegalArgumentException` shows it.
                let bind = e.get_ref().and_then(|inner| inner.downcast_ref::<mock_server::BindFailure>());
                if let Some(bind) = bind {
                    cli::main_line(&logger_config, &logger_config.log_level(), "ERROR", &format!("{} \n{bind}", bind.message()));
                }
                let shown = e.to_string();
                cli::main_line(&logger_config, &logger_config.log_level(), "ERROR", &format!("exception while starting:{{}} \n{shown}"));
                // `Main`: with the console handler gone, the failure goes to stderr instead
                if cli::system_out_disabled(&logger_config) {
                    eprintln!("java.lang.RuntimeException: exception while starting: {}", bind.map_or_else(|| e.to_string(), |b| format!("Exception while binding MockServer to port {}", b.port)));
                }
                return ExitCode::from(1);
            }
        };
        cli::logger_level_line(&logger_config);
        let port = server.ports().first().copied().unwrap_or(0);
        match after {
            After::Nothing => {}
            After::Ui => emit(&cli::open_dashboard(port, &env), ""),
            After::Demo => {
                let demo_config = logger_config.clone();
                let seeded = tokio::task::spawn_blocking(move || {
                    for expectation in cli::DEMO_EXPECTATIONS {
                        if let Err(e) = cli::put_json("localhost", i32::from(port), "/mockserver/expectation", expectation) {
                            cli::main_line(&demo_config, &demo_config.log_level(), "WARN", &format!("exception while seeding demo expectations:{{}} \n{e}"));
                            return;
                        }
                    }
                })
                .await;
                let _ = seeded;
                emit(&cli::demo_instructions(port), "");
            }
        }
        // As a process, 8.0.0 exits once a stop closes the listeners: the JVM's one non-daemon thread waits on the
        // server channel's `closeFuture`, so the drain (`stopDrainMillis`) runs on a daemon thread the exit cuts
        // short, and in-flight requests lose their connections. Only an in-process `Server` drains.
        tokio::select! {
            _ = server.closing() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        ExitCode::SUCCESS
    });
    // like the JVM's daemon threads, nothing still running (the drain, a delayed response, a blocking task) holds the exit
    runtime.shutdown_background();
    cli::flush_console();
    code
}

/// `SIGTERM` (`docker stop`, `kill`) still ends the process as its default action does, but only once the queued
/// console lines are written: the handler flushes them, restores the default disposition and raises the signal again.
/// Where the default action ignores it (PID 1 of a container without an init), the process runs on, as before.
#[cfg(unix)]
fn flush_on_terminate() {
    let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else { return };
    tokio::spawn(async move {
        if terminate.recv().await.is_some() {
            cli::flush_console();
            // SAFETY: restoring the default action of a signal and raising it have no memory-safety preconditions
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::raise(libc::SIGTERM);
            }
        }
    });
}

/// Docker `HEALTHCHECK`: `PUT /mockserver/status` on the first configured port, like `org.mockserver.cli.HealthCheck`.
fn healthcheck() -> ExitCode {
    use std::io::Read;
    let port = healthcheck_port(|name| std::env::var(name).ok());
    let Ok(port) = u16::try_from(port) else { return ExitCode::FAILURE };
    // upstream's Go healthcheck dials `localhost`, ::1 first and 127.0.0.1 only when that fails; the first connection
    // on a local address renders its `localAddress` with a host name, so ours takes the same address
    let loopbacks = [std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
    let Some(mut stream) = loopbacks.iter().find_map(|ip| std::net::TcpStream::connect((*ip, port)).ok()) else {
        return ExitCode::FAILURE;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let request = format!("PUT /mockserver/status HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let mut response = [0u8; 16];
    if stream.write_all(request.as_bytes()).is_err() || stream.read(&mut response).is_err() {
        return ExitCode::FAILURE;
    }
    if response.starts_with(b"HTTP/1.1 200") { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `HealthCheck.resolvePort`: `MOCKSERVER_SERVER_PORT`, else `SERVER_PORT` (an empty one counts as unset), its first
/// comma-separated entry read by `Integer.parseInt`; 1080 when neither is set or the entry is not an int.
fn healthcheck_port(env: impl Fn(&str) -> Option<String>) -> i32 {
    let set = |name: &str| env(name).filter(|v| !v.is_empty());
    match set("MOCKSERVER_SERVER_PORT").or_else(|| set("SERVER_PORT")) {
        Some(ports) => ports.split(',').next().unwrap_or_default().trim().parse().unwrap_or(1080),
        None => 1080,
    }
}

#[cfg(test)]
mod tests {
    use super::healthcheck_port;

    /// `HealthCheckTest.shouldReturnDefaultPortWhenNoEnvSet`, and the rest of `resolvePort`.
    #[test]
    fn healthcheck_port_is_the_first_configured_port_else_1080() {
        let port = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            healthcheck_port(|name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        };
        assert_eq!(port(&[]), 1080);
        assert_eq!(port(&[("SERVER_PORT", "1234")]), 1234);
        assert_eq!(port(&[("MOCKSERVER_SERVER_PORT", " 2345 ,3456"), ("SERVER_PORT", "1234")]), 2345);
        assert_eq!(port(&[("MOCKSERVER_SERVER_PORT", ""), ("SERVER_PORT", "1234")]), 1234);
        assert_eq!(port(&[("MOCKSERVER_SERVER_PORT", "abc"), ("SERVER_PORT", "1234")]), 1080);
        assert_eq!(port(&[("SERVER_PORT", "+99")]), 99);
    }
}
