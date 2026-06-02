fn main() {
    match keli_cli::parse_cli_command(std::env::args().skip(1)) {
        Ok(command) => {
            if let Err(error) = keli_cli::run(command) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            let _ = keli_cli::print_usage(std::io::stderr());
            std::process::exit(2);
        }
    }
}
