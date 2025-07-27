use rusqlite::Connection;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2,
};
use crate::error::{AuthError, AuthResult};

/// Configuração de validação de senha
pub struct PasswordConfig {
    pub min_length: usize,
    pub require_digit: bool,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_special: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        PasswordConfig {
            min_length: 8,
            require_digit: true,
            require_uppercase: false,
            require_lowercase: false,
            require_special: false,
        }
    }
}

/// Valida as credenciais de entrada
fn validate_credentials(username: &str, password: &str) -> AuthResult<()> {
    if username.is_empty() {
        return Err(AuthError::Validation("Nome de usuário não pode estar vazio".to_string()));
    }
    
    if password.is_empty() {
        return Err(AuthError::Validation("Senha não pode estar vazia".to_string()));
    }
    
    Ok(())
}

/// Valida a força da senha com base na configuração
fn validate_password_strength(password: &str, config: &PasswordConfig) -> AuthResult<()> {
    if password.len() < config.min_length {
        return Err(AuthError::Validation(
            format!("A senha deve ter pelo menos {} caracteres", config.min_length)
        ));
    }
    
    if config.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::Validation("A senha deve conter pelo menos um número".to_string()));
    }
    
    if config.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AuthError::Validation("A senha deve conter pelo menos uma letra maiúscula".to_string()));
    }
    
    if config.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(AuthError::Validation("A senha deve conter pelo menos uma letra minúscula".to_string()));
    }
    
    if config.require_special && !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
        return Err(AuthError::Validation("A senha deve conter pelo menos um caractere especial".to_string()));
    }
    
    Ok(())
}

/// Gera o hash da senha usando Argon2
fn hash_password(password: &str) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHashing(format!("Erro ao hashear senha: {}", e)))?
        .to_string();
    
    Ok(password_hash)
}

/// Verifica se a senha corresponde ao hash armazenado
fn verify_password(password: &str, stored_hash: &str) -> AuthResult<bool> {
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(stored_hash)
        .map_err(|e| AuthError::PasswordHashing(format!("Erro ao analisar hash: {}", e)))?;
    
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

/// Hash dummy para prevenir timing attacks
fn dummy_hash_operation() {
    let dummy_salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let _ = argon2.hash_password(b"dummy_password", &dummy_salt);
}

/// Registra um novo usuário no sistema
pub fn register_user(conn: &Connection, username: &str, password: &str) -> AuthResult<()> {
    // Validações de entrada
    validate_credentials(username, password)?;
    
    // Validação de força da senha
    let config = PasswordConfig::default();
    validate_password_strength(password, &config)?;
    
    // Verificar se usuário já existe primeiro (mais eficiente)
    let user_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM users WHERE username = ?1",
        [username],
        |row| row.get(0),
    )?;
    
    if user_exists {
        return Err(AuthError::Validation(format!("Usuário '{}' já existe", username)));
    }
    
    // Gerar hash da senha
    let password_hash = hash_password(password)?;
    
    // Inserir usuário no banco
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        [username, &password_hash],
    )?;
    
    Ok(())
}

/// Realiza o login de um usuário
pub fn login_user(conn: &Connection, username: &str, password: &str) -> AuthResult<bool> {
    use rusqlite::OptionalExtension;
    
    // Validações de entrada
    validate_credentials(username, password)?;
    
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
            // Hash dummy para prevenir timing attacks
            dummy_hash_operation();
            return Ok(false);
        }
    };
    
    // Verificar a senha
    let is_valid = verify_password(password, &stored_hash)?;
    
    Ok(is_valid)
}

/// Altera a senha de um usuário existente
pub fn change_password(conn: &Connection, username: &str, old_password: &str, new_password: &str) -> AuthResult<()> {
    // Primeiro, verificar se a senha atual está correta
    if !login_user(conn, username, old_password)? {
        return Err(AuthError::Validation("Senha atual incorreta".to_string()));
    }
    
    // Validar a nova senha
    let config = PasswordConfig::default();
    validate_password_strength(new_password, &config)?;
    
    // Gerar novo hash
    let new_hash = hash_password(new_password)?;
    
    // Atualizar no banco
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE username = ?2",
        [&new_hash, username],
    )?;
    
    Ok(())
}