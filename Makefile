# Makefile simples para Java para testar com user1 de forma rapida, estar na pasta Sperta

# Variáveis
JAVAC = javac
JAVA = java
SRC_DIR = src
BIN_DIR = bin

# Deteta o sistema operativo para comandos específicos
ifeq ($(OS),Windows_NT)
    MKDIR = if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"
    RM = rmdir /s /q "$(BIN_DIR)"
    RM_FILES = del /f /q
    SEP = ;
else
    MKDIR = mkdir -p $(BIN_DIR)
    RM = rm -rf $(BIN_DIR)
    RM_FILES = rm -f
    SEP = :
endif

# Alvo padrão (compila tudo)
all: server client

# Compilar servidor
server:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/CryptoService.java $(SRC_DIR)/server/SpertaServer.java

# Compilar cliente
client:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/CryptoService.java $(SRC_DIR)/client/SpertaClient.java

# Executar servidor
run-server: server
	$(JAVA) -cp $(BIN_DIR) server.SpertaServer 22345 server-pw keystores/keystore.server 123456

# Executar clientes
# Nota: Alterar os argumentos conforme necessário (ex: password da keystore)
run-client: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user1 123456 keystores/users/keystore.user1 123456 user1 1234

run-client2: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user2 123456 keystores/users/keystore.user2 123456 user2 1234

run-client3: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user3 123456 keystores/users/keystore.user3 123456 user3 1234

# Criar JARs
jar: all
	jar cfe SpertaServer.jar server.SpertaServer -C $(BIN_DIR) server
	jar cfe SpertaClient.jar client.SpertaClient -C $(BIN_DIR) client

# Executar a partir dos JARs
run-server-jar:
	$(JAVA) -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456

run-client-jar:
	$(JAVA) -jar SpertaClient.jar 127.0.0.1:22345 keystores/users/truststore.user1 123456 keystores/users/keystore.user1 123456 user1 1234

# Limpar binários e JARs
clean:
	-$(RM)
	-$(RM_FILES) SpertaServer.jar SpertaClient.jar
