fn main() {
    if let Err(err) = connect::run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

