use rusqlite::Connection;
use crate::error::{AuthError, AuthResult};

const DB_FILE: &str = "users.db";

/// Estrutura para gerenciar a conexão com o banco de dados
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Cria uma nova instância do banco de dados
    pub fn new() -> AuthResult<Self> {
        let conn = Connection::open(DB_FILE)?;
        let db = Database { conn };
        db.init_tables()?;
        Ok(db)
    }

    /// Inicializa as tabelas necessárias
    fn init_tables(&self) -> AuthResult<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        Ok(())
    }

    /// Retorna uma referência para a conexão
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Verifica se um usuário existe
    pub fn user_exists(&self, username: &str) -> AuthResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            [username],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Obtém o hash da senha de um usuário
    pub fn get_password_hash(&self, username: &str) -> AuthResult<Option<String>> {
        use rusqlite::OptionalExtension;
        
        let hash = self.conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            [username],
            |row| row.get(0),
        ).optional()?;
        
        Ok(hash)
    }

    /// Insere um novo usuário no banco
    pub fn insert_user(&self, username: &str, password_hash: &str) -> AuthResult<()> {
        match self.conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
            [username, password_hash],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(AuthError::Validation(format!("Usuário '{}' já existe", username)))
            }
            Err(e) => Err(AuthError::from(e)),
        }
    }

    /// Lista todos os usuários com informações de criação
    pub fn list_users(&self) -> AuthResult<Vec<(i32, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, datetime(created_at, 'localtime') as created 
             FROM users ORDER BY username"
        )?;
        
        let user_iter = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;

        let mut users = Vec::new();
        for user in user_iter {
            users.push(user?);
        }
        Ok(users)
    }

    /// Deleta um usuário (para fins administrativos)
    pub fn delete_user(&self, username: &str) -> AuthResult<bool> {
        let rows_affected = self.conn.execute(
            "DELETE FROM users WHERE username = ?1",
            [username],
        )?;
        Ok(rows_affected > 0)
    }

    /// Obtém estatísticas do banco
    pub fn get_stats(&self) -> AuthResult<DatabaseStats> {
        let user_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users",
            [],
            |row| row.get(0),
        )?;

        use rusqlite::OptionalExtension;
        
        let latest_user: Option<String> = self.conn.query_row(
            "SELECT username FROM users ORDER BY created_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).optional()?;

        Ok(DatabaseStats {
            total_users: user_count as usize,
            latest_user,
        })
    }
}

/// Estrutura para estatísticas do banco
#[derive(Debug)]
pub struct DatabaseStats {
    pub total_users: usize,
    pub latest_user: Option<String>,
}