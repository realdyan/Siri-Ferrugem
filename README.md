# Siri-Ferrugem

Sistema de Autenticação "Siri" em Rust

Este é um projeto de console simples, desenvolvido em Rust, que demonstra um sistema de autenticação de usuários seguro. Ele permite registrar novos usuários e fazer login, com as senhas sendo armazenadas de forma segura usando o algoritmo Argon2 e persistidas em um banco de dados SQLite.

🚀 Funcionalidades Principais

    Registro de Novos Usuários: Inclui validações de entrada, como tamanho mínimo de senha e a exigência de conter números.

    Login de Usuários Existentes: Autentica usuários comparando a senha fornecida com o hash armazenado.

    Hashing de Senhas Seguro: Utiliza o Argon2, o padrão recomendado para hashing de senhas, para proteger as credenciais dos usuários.

    Armazenamento Persistente: Salva os dados dos usuários em um banco de dados SQLite (users.db).

    Entrada de Senha Oculta: A senha não é exibida no terminal durante a digitação, para maior segurança.

    Interface de Linha de Comando (CLI): Um menu interativo simples para guiar o usuário.

🛠️ Tecnologias e Crates Utilizados

    Linguagem: Rust

    Banco de Dados: rusqlite para interação com o SQLite.

    Hashing de Senha: argon2 para hashing e verificação seguros.

    Entrada Segura: rpassword para ler a senha sem exibi-la no terminal.

⚙️ Como Usar

Pré-requisitos

É necessário ter o toolchain do Rust instalado. Você pode instalá-lo através do rustup.

Passos para Execução

    Clone o repositório:
    Bash

git clone <URL_DO_SEU_REPOSITORIO_GIT>

Navegue até o diretório do projeto:
Bash

cd Siri-Ferrugem

Compile e execute o projeto:
Bash

cargo run

O programa irá iniciar e exibir o menu de opções. O banco de dados users.db será criado automaticamente no diretório do projeto na primeira execução.

Para uma compilação otimizada, você pode usar:
Bash

cargo build --release

E então executar o binário diretamente:
Bash

    ./target/release/Siri

📜 Licença

Este projeto é licenciado sob a Licença MIT. Veja o texto completo abaixo.

MIT License

Copyright (c) 2025 [Dyan Alencar de Oliveira]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
