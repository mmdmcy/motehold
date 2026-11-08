use std::{env, io};

mod app;
mod features;
mod interfaces;
mod persistence;
mod security;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "serve" => app::serve().await,
        "hash-password" => {
            security::auth::hash_password_cmd(&args[1..])?;
            Ok(())
        }
        "audit-public" => {
            if security::public_audit::audit_public_cmd(&args[1..])? != 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        _ => {
            eprintln!("usage: motehold [serve|hash-password --stdin|audit-public]");
            Ok(())
        }
    }
}
