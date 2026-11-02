//! `aza-node`: runs an aza node.
//!
//! ```text
//! aza-node --url https://node.example [--listen 0.0.0.0:8080] [--db aza-node.db]
//!          [--min-work 6] [--quota 1000000]
//! ```
use aza_node::Config;

fn usage() -> ! {
    eprintln!(
        "usage: aza-node --url <public URL> [--listen <addr>] [--db <file>] [--min-work <bits>] [--quota <bytes>]"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut url = None;
    let mut listen = "127.0.0.1:8080".to_string();
    let mut db = Some("aza-node.db".to_string());
    let mut min_work = None;
    let mut quota = None;
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--url" => url = Some(val()),
            "--listen" => listen = val(),
            "--db" => db = Some(val()),
            "--min-work" => min_work = Some(val().parse().unwrap_or_else(|_| usage())),
            "--quota" => quota = Some(val().parse().unwrap_or_else(|_| usage())),
            _ => usage(),
        }
    }
    let mut config = Config::new(&url.unwrap_or_else(|| usage()));
    config.db = db;
    if let Some(w) = min_work {
        config.min_work = w;
    }
    if let Some(q) = quota {
        config.quota = q;
    }
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("aza node {} listening on {listen}", config.url);
    aza_node::serve(config, listener).await
}
