const BANNER: &str = r#"
 _                                 ___ ____
| |__   _____  ____ _ _ __   ___  / __\___ \
| '_ \ / _ \ \/ / _` | '_ \ / _ \/ /    __) |
| | | |  __/>  < (_| | | | |  __/ /___ / __/
|_| |_|\___/_/\_\__,_|_| |_|\___\____/|_____|
"#;

pub struct Client {
    // implement with crossterm
}

impl Client {
    fn print_banner() {
        println!("{}", BANNER);
    }

    pub fn run_client() {
        Self::print_banner();
    }
}

