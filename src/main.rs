use std::process;

use yacli::cli::{Command, McpTransportArg, parse_cli};
use yacli::commands::execute;
use yacli::mcp::server::{serve_http, serve_stdio};
use yacli::output::emit;

/// Дерево команд clap большое: в отладочной сборке на Windows (главный поток
/// получает только 1 МБ стека) разбор аргументов переполняет стек, поэтому
/// всё выполняется в потоке с запасом.
const MAIN_STACK_BYTES: usize = 32 * 1024 * 1024;

fn main() {
    let worker = std::thread::Builder::new()
        .name("yacli-main".to_string())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(run)
        .expect("failed to spawn the main worker thread");
    if worker.join().is_err() {
        process::exit(101);
    }
}

fn run() {
    let cli = parse_cli();
    if let Command::Mcp {
        transport,
        listen,
        public_url,
    } = &cli.command
    {
        let result = match transport {
            McpTransportArg::Stdio => serve_stdio(),
            McpTransportArg::Http => serve_http(listen, public_url.as_deref()),
        };
        if let Err(err) = result {
            err.exit();
        }
        return;
    }
    match execute(cli) {
        Ok(rendered) => {
            let exit_code = rendered.exit_code;
            emit(rendered);
            if exit_code != 0 {
                process::exit(exit_code);
            }
        }
        Err(err) => err.exit(),
    }
}
