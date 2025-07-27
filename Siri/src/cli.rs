use std::io::{self, Write};
use crate::auth::{register_user, login_user};
use crate::db::Database;
use crate::error::{AuthError, AuthResult};

/// Estrutura para gerenciar a interface CLI
pub struct CLI {
    db: Database,
}

impl CLI {
    /// Cria uma nova instância da CLI
    pub fn new() -> AuthResult<Self> {
        let db = Database::new()?;
        Ok(CLI { db })
    }

    /// Executa o loop principal da aplicação
    pub fn run(&self) -> AuthResult<()> {
        self.show_welcome();

        loop {
            match self.show_menu_and_get_choice()? {
                MenuChoice::Register => self.handle_register()?,
                MenuChoice::Login => self.handle_login()?,
                MenuChoice::ListUsers => self.handle_list_users()?,
                MenuChoice::Exit => {
                    println!("👋 Encerrando o sistema. Até logo!");
                    break;
                }
                MenuChoice::Invalid => {
                    println!("❌ Opção inválida. Tente novamente.");
                }
            }
            println!(); // Linha em branco para melhor visibilidade
        }
        Ok(())
    }

    /// Mostra a mensagem de boas-vindas
    fn show_welcome(&self) {
        println!("==  Siri Ferrugem  ==");
        println!("=====================");
        println!("\n");
    }

    /// Mostra o menu e obtém a escolha do usuário
    fn show_menu_and_get_choice(&self) -> AuthResult<MenuChoice> {
        println!("📋 Escolha uma opção:");
        println!("1️⃣  Registrar novo usuário");
        println!("2️⃣  Fazer login");
        println!("3️⃣  Listar usuários");
        println!("4️⃣  Sair");
        println!();
        
        print!("👉 Opção: ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        Ok(MenuChoice::from_str(choice.trim()))
    }

    /// Lida com o registro de usuário
    fn handle_register(&self) -> AuthResult<()> {
        println!("\n📝 REGISTRO DE NOVO USUÁRIO");
        
        let username = self.read_username()?;
        
        if username.is_empty() {
            println!("⚠️  Nome de usuário não pode estar vazio.");
            return Ok(());
        }
        
        let password = self.read_password("🔒 Senha (oculta): ")?;
        let confirm_password = self.read_password("🔒 Confirme a senha (oculta): ")?;
        
        if password != confirm_password {
            println!("⚠️  As senhas não coincidem.");
            return Ok(());
        }
        
        match register_user(self.db.connection(), &username, &password) {
            Ok(_) => println!("✅ Usuário '{}' registrado com sucesso!", username),
            Err(AuthError::Validation(msg)) => println!("⚠️  {}", msg),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Lida com o login de usuário
    fn handle_login(&self) -> AuthResult<()> {
        println!("\n🔓 LOGIN");
        
        let username = self.read_username()?;
        
        if username.is_empty() {
            println!("⚠️  Nome de usuário não pode estar vazio.");
            return Ok(());
        }
        
        let password = self.read_password("🔒 Senha (oculta): ")?;
        
        if password.is_empty() {
            println!("⚠️  Senha não pode estar vazia.");
            return Ok(());
        }
        
        match login_user(self.db.connection(), &username, &password) {
            Ok(true) => {
                println!("✅ Login de '{}' bem-sucedido!", username);
                // Aqui você poderia adicionar um menu pós-login
                self.show_user_menu(&username)?;
            },
            Ok(false) => println!("❌ Credenciais inválidas."),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Lida com a listagem de usuários
    fn handle_list_users(&self) -> AuthResult<()> {
        println!("\n👥 USUÁRIOS CADASTRADOS");
        
        let users = self.db.list_users()?;
        
        if users.is_empty() {
            println!("📭 Nenhum usuário cadastrado.");
        } else {
            println!("📊 Total de usuários: {}\n", users.len());
            for (id, username, created_at) in users {
                println!("🆔 #{:<3} | 👤 {:<20} | 📅 {}", id, username, created_at);
            }
        }
        Ok(())
    }

    /// Lê o nome de usuário
    fn read_username(&self) -> AuthResult<String> {
        print!("👤 Nome de usuário: ");
        io::stdout().flush()?;
        
        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        
        Ok(username.trim().to_string())
    }

    /// Lê a senha de forma segura
    fn read_password(&self, prompt: &str) -> AuthResult<String> {
        use rpassword::read_password;
        
        print!("{}", prompt);
        io::stdout().flush()?;
        
        let password = read_password()?;
        Ok(password)
    }

    /// Menu pós-login para operações do usuário
    fn show_user_menu(&self, username: &str) -> AuthResult<()> {
        loop {
            println!("\n🏠 MENU DO USUÁRIO - {}", username.to_uppercase());
            println!("1️⃣  Alterar senha");
            println!("2️⃣  Ver informações da conta");
            println!("3️⃣  Sair da conta");
            println!();
            
            print!("👉 Opção: ");
            io::stdout().flush()?;
            
            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;
            
            match choice.trim() {
                "1" => self.handle_change_password(username)?,
                "2" => self.show_account_info(username)?,
                "3" => {
                    println!("🚪 Saindo da conta de '{}'...", username);
                    break;
                }
                _ => println!("❌ Opção inválida. Tente novamente."),
            }
        }
        Ok(())
    }

    /// Lida com a alteração de senha
    fn handle_change_password(&self, username: &str) -> AuthResult<()> {
        use crate::auth::change_password;
        
        println!("\n🔄 ALTERAR SENHA");
        
        let old_password = self.read_password("🔒 Senha atual (oculta): ")?;
        let new_password = self.read_password("🔒 Nova senha (oculta): ")?;
        let confirm_password = self.read_password("🔒 Confirme a nova senha (oculta): ")?;
        
        if new_password != confirm_password {
            println!("⚠️  As senhas não coincidem.");
            return Ok(());
        }
        
        match change_password(self.db.connection(), username, &old_password, &new_password) {
            Ok(_) => println!("✅ Senha alterada com sucesso!"),
            Err(AuthError::Validation(msg)) => println!("⚠️  {}", msg),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Mostra informações da conta
    fn show_account_info(&self, username: &str) -> AuthResult<()> {
        println!("\n👤 INFORMAÇÕES DA CONTA");
        println!("📛 Nome de usuário: {}", username);
        
        // Buscar informações adicionais do banco se necessário
        let user_count = self.db.list_users()?.len();
        println!("👥 Total de usuários no sistema: {}", user_count);
        
        println!("🔐 Status: Conta ativa");
        Ok(())
    }
}

/// Enum para as escolhas do menu
#[derive(Debug)]
enum MenuChoice {
    Register,
    Login,
    ListUsers,
    Exit,
    Invalid,
}

impl MenuChoice {
    fn from_str(s: &str) -> Self {
        match s {
            "1" => MenuChoice::Register,
            "2" => MenuChoice::Login,
            "3" => MenuChoice::ListUsers,
            "4" => MenuChoice::Exit,
            _ => MenuChoice::Invalid,
        }
    }
}