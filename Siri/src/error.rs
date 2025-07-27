use std::fmt;

/// Enum para diferentes tipos de erros do sistema
#[derive(Debug)]
pub enum AuthError {
    Database(rusqlite::Error),
    PasswordHashing(String),
    Validation(String),
    Input(std::io::Error),
    NotFound(String),
    PermissionDenied(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Database(err) => write!(f, "Erro de banco de dados: {}", err),
            AuthError::PasswordHashing(msg) => write!(f, "Erro ao processar senha: {}", msg),
            AuthError::Validation(msg) => write!(f, "Erro de validação: {}", msg),
            AuthError::Input(err) => write!(f, "Erro de entrada: {}", err),
            AuthError::NotFound(msg) => write!(f, "Não encontrado: {}", msg),
            AuthError::PermissionDenied(msg) => write!(f, "Permissão negada: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<rusqlite::Error> for AuthError {
    fn from(err: rusqlite::Error) -> Self {
        AuthError::Database(err)
    }
}

impl From<std::io::Error> for AuthError {
    fn from(err: std::io::Error) -> Self {
        AuthError::Input(err)
    }
}

/// Tipo Result personalizado para o sistema
pub type AuthResult<T> = Result<T, AuthError>;

/// Macro para criar erros de validação rapidamente
#[macro_export]
macro_rules! validation_error {
    ($msg:expr) => {
        Err(crate::error::AuthError::Validation($msg.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        Err(crate::error::AuthError::Validation(format!($fmt, $($arg)*)))
    };
}