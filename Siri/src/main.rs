use rusqlite::{Connection, OptionalExtension, Result};
use argon2::{
    password_hash::{
        rand_core::OsRng, 
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2,
};
use std::io::{self, Write};
use rpassword::read_password;

const DB_FILE: &str = "users.db";

/// Inicializa o banco de dados e cria a tabela de usuários
fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Lê a senha de forma segura (oculta no terminal)
fn read_password_securely(prompt: &str) -> std::io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    read_password()
}

/// Registra um novo usuário no sistema
fn register_user(conn: &Connection, username: &str, password: &str) -> Result<()> {
    // Validações de entrada
    if username.is_empty() || password.is_empty() {
        println!("⚠️  Nome de usuário e senha não podem estar vazios.");
        return Ok(());
    }

    if password.len() < 8 {
        println!("⚠️  A senha deve ter pelo menos 8 caracteres.");
        return Ok(());
    }

    // Validação adicional de senha forte
    if !password.chars().any(|c| c.is_ascii_digit()) {
        println!("⚠️  A senha deve conter pelo menos um número.");
        return Ok(());
    }

    // Gerar salt e hashear a senha
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
                Some(format!("Erro ao hashear senha: {}", e)),
            )
        })?
        .to_string();

    // Inserir usuário no banco
    match conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        [username, &password_hash],
    ) {
        Ok(_) => println!("✅ Usuário '{}' registrado com sucesso!", username),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            println!("❌ Erro: Usuário '{}' já existe.", username);
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Realiza o login de um usuário
fn login_user(conn: &Connection, username: &str, password: &str) -> Result<bool> {
    // Validações de entrada
    if username.is_empty() || password.is_empty() {
        println!("⚠️  Nome de usuário e senha não podem estar vazios.");
        return Ok(false);
    }

    // Buscar hash da senha no banco
    let stored_hash: Option<String> = conn
        .query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            [username],
            |row| row.get(0),
        )
        .optional()?;

    // Verificar se usuário existe
    let stored_hash = match stored_hash {
        Some(hash) => hash,
        None => {
            println!("❌ Usuário '{}' não encontrado.", username);
            // Hash dummy para prevenir timing attacks
            let dummy_salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let _ = argon2.hash_password(b"dummy_password", &dummy_salt);
            return Ok(false);
        }
    };

    // Verificar a senha
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&stored_hash).map_err(|e| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
            Some(format!("Erro ao analisar hash: {}", e)),
        )
    })?;

    let is_valid = argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    if is_valid {
        println!("✅ Login de '{}' bem-sucedido!", username);
    } else {
        println!("❌ Senha incorreta para o usuário '{}'.", username);
    }

    Ok(is_valid)
}

fn main() -> Result<()> {
    // Conectar ao banco de dados
    let conn = Connection::open(DB_FILE)?;
    init_db(&conn)?;

    println!("🔐 Sistema de Autenticação Rust + SQLite");
    println!("🛡️  Usando Argon2 para hash seguro de senhas");
    println!("👁️‍🗨️  Senhas são ocultadas durante a digitação\n");

    loop {
        println!("📋 Escolha uma opção:");
        println!("1️⃣  Registrar novo usuário");
        println!("2️⃣  Fazer login");
        println!("3️⃣  Sair");

        print!("👉 Opção: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                println!("\n📝 REGISTRO DE NOVO USUÁRIO");
                print!("👤 Nome de usuário: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                let username = username.trim();

                let password = match read_password_securely("🔒 Senha (oculta): ") {
                    Ok(pass) => pass,
                    Err(e) => {
                        eprintln!("❌ Erro ao ler senha: {}", e);
                        continue;
                    }
                };

                if let Err(e) = register_user(&conn, username, &password) {
                    eprintln!("❌ Erro ao registrar usuário: {:?}", e);
                }
            }
            "2" => {
                println!("\n🔓 LOGIN");
                print!("👤 Nome de usuário: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                let username = username.trim();

                let password = match read_password_securely("🔒 Senha (oculta): ") {
                    Ok(pass) => pass,
                    Err(e) => {
                        eprintln!("❌ Erro ao ler senha: {}", e);
                        continue;
                    }
                };

                if let Err(e) = login_user(&conn, username, &password) {
                    eprintln!("❌ Erro ao fazer login: {:?}", e);
                }
            }
            "3" => {
                println!("👋 Encerrando o sistema. Até logo!");
                break;
            }
            _ => {
                println!("❌ Opção inválida. Tente novamente.");
            }
        }
        
        println!(); // Linha em branco para melhor visibilidade
    }

    Ok(())
}