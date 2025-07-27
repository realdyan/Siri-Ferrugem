mod auth;
mod cli;
mod db;
mod error;

use cli::CLI;
use error::AuthResult;

fn main() -> AuthResult<()> {
    let cli = CLI::new()?;
    cli.run()?;
    Ok(())
}