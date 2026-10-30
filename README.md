# PROJETO 2 - SC 2025/2026
## Sistema Distribuído Sperta

---

### AUTORES
- **Diogo Chambel** - 53319
- **Márcio Moreira** - 41972
- **Nuno Graxinha** - 59855

---

### DESENVOLVIMENTO
O projeto foi desenvolvido em ambiente Windows

---

### COMPILAÇÃO
O projeto inclui um `Makefile` para facilitar o processo. Na raiz do projeto (`Sperta/`), execute:

make

Para compilar e gerar os ficheiros executáveis (`.jar`) do Cliente e Servidor, execute:

make jar

Isto irá criar a diretoria `bin/` e gerar o `SpertaServer.jar` e `SpertaClient.jar`.

Para limpar as diretorias compiladas e os JARs:

make clean

---

### EXECUÇÃO (Fase 2 - Criptografia, TLS e E2E)

#### [ SERVIDOR ]

Para iniciar a aplicação do servidor com o **Makefile** (utiliza o porto `22345` e a keystore pré-definida):

make run-server

Ou diretamente através do **.jar** compilado pelo Makefile:

make run-server-jar

**De forma manual (via JAR):**
java -jar SpertaServer.jar <porto> <password-cifra> <caminho-keystore> <password-keystore-server>

*Exemplo:* `java -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456`

**De forma manual (via classes compiladas):**
java -cp bin server.SpertaServer <porto> <password-cifra> <caminho-keystore> <password-keystore-server>

---

#### [ CLIENTE ]

Para iniciar o cliente e autenticar no servidor via **Makefile** (utiliza o `user1` por omissão):

make run-client

Ou diretamente através do **.jar** compilado pelo Makefile:

make run-client-jar

**De forma manual (via JAR):**
java -jar SpertaClient.jar <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>

*Exemplo:* `java -jar SpertaClient.jar 127.0.0.1:22345 keystores/truststore.client 123456 keystores/users/keystore.user1 123456 user1 1234`

**De forma manual (via classes compiladas):**
java -cp bin client.SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>