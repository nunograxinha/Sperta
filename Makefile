# Makefile for Sperta Project

JAVAC = javac
JAVA = java
SRC_DIR = src
BIN_DIR = bin

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

all: server client

# Compile Server & Shared Utils
server:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/*.java $(SRC_DIR)/server/*.java
	
# Compile Client & Shared Utils
client:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/*.java $(SRC_DIR)/client/*.java

# Run Server in Classpath mode
run-server: server
	$(JAVA) -cp $(BIN_DIR) server.SpertaServer 22345 server-pw keystores/keystore.server 123456

# Run Clients in Classpath mode
run-client: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user1 123456 keystores/users/keystore.user1 123456 user1 1234

run-client2: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user2 123456 keystores/users/keystore.user2 123456 user2 1234

run-client3: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 keystores/users/truststore.user3 123456 keystores/users/keystore.user3 123456 user3 1234

# Package executable JARs including utils
server-jar: server
	jar cfe SpertaServer.jar server.SpertaServer -C $(BIN_DIR) server -C $(BIN_DIR) utils

client-jar: client
	jar cfe SpertaClient.jar client.SpertaClient -C $(BIN_DIR) client -C $(BIN_DIR) utils

jar: server-jar client-jar

# Run from packaged JARs
run-server-jar: server-jar
	$(JAVA) -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456

run-client-jar: client-jar
	$(JAVA) -jar SpertaClient.jar 127.0.0.1:22345 keystores/users/truststore.user1 123456 keystores/users/keystore.user1 123456 user1 1234
clean:
	-$(RM)
	-$(RM_FILES) SpertaServer.jar SpertaClient.jar