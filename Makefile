# ==============================================================================
# Makefile - Sperta Smart Home Project
# ==============================================================================

JAVAC   = javac
JAVA    = java
SRC_DIR = src
BIN_DIR = bin

# Path to JavaFX JARs (local lib folder or absolute SDK path)
PATH_TO_FX = lib

# Operating System Detection
ifeq ($(OS),Windows_NT)
    MKDIR    = if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"
    RM       = if exist "$(BIN_DIR)" rmdir /s /q "$(BIN_DIR)"
    RM_FILES = del /f /q 2>nul
    SEP      = ;
else
    MKDIR    = mkdir -p $(BIN_DIR)
    RM       = rm -rf $(BIN_DIR)
    RM_FILES = rm -f
    SEP      = :
endif

.PHONY: all server client gui jar server-jar client-jar run-server run-client run-client2 run-client3 run-gui run-server-jar run-client-jar clean

all: server client

# ------------------------------------------------------------------------------
# Compilation Targets
# ------------------------------------------------------------------------------
compile:
	javac -d bin $(shell find src -name "*.java")
	@mkdir -p bin/client/gui
	@cp src/client/gui/styles.css bin/client/gui/ 2>/dev/null || true
	
# Compile Server and shared utilities
server:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/*.java $(SRC_DIR)/server/*.java

# Compile CLI Client and shared utilities
client:
	$(MKDIR)
	$(JAVAC) -d $(BIN_DIR) $(SRC_DIR)/utils/*.java $(SRC_DIR)/client/*.java

# Compile JavaFX Graphical User Interface
gui:
	@if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"
	@if not exist "$(BIN_DIR)\client\gui" mkdir "$(BIN_DIR)\client\gui"
	$(JAVAC) -d $(BIN_DIR) src/utils/*.java src/client/*.java
	$(JAVAC) --module-path "$(PATH_TO_FX)" --add-modules javafx.controls,javafx.fxml -cp "$(BIN_DIR)" -d $(BIN_DIR) src/client/gui/*.java
	@xcopy /y /q "src\client\gui\*.css" "$(BIN_DIR)\client\gui\" >nul 2>&1 || (copy /y "src\client\gui\*.css" "$(BIN_DIR)\client\gui\" >nul 2>&1)
	@xcopy /y /q "src\client\gui\*.png" "$(BIN_DIR)\client\gui\" >nul 2>&1 || (copy /y "src\client\gui\*.png" "$(BIN_DIR)\client\gui\" >nul 2>&1)

# ------------------------------------------------------------------------------
# Execution Targets (Classpath Mode)
# ------------------------------------------------------------------------------

# Start the TLS Server
run-server: server
	$(JAVA) -cp $(BIN_DIR) server.SpertaServer 22345 server-pw keystores/keystore.server 123456

# Run CLI Client instances
run-client: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 user1 1234

run-client2: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 user2 1234

run-client3: client
	$(JAVA) -cp $(BIN_DIR) client.SpertaClient 127.0.0.1:22345 user3 1234

# Compile and run the JavaFX GUI
run-gui: gui
	$(JAVA) --module-path "$(PATH_TO_FX)" --add-modules javafx.controls,javafx.fxml -Djava.library.path="$(PATH_TO_FX)" -cp $(BIN_DIR) client.gui.Main
# ------------------------------------------------------------------------------
# JAR Packaging Targets
# ------------------------------------------------------------------------------

server-jar: server
	jar cfe SpertaServer.jar server.SpertaServer -C $(BIN_DIR) server -C $(BIN_DIR) utils

client-jar: client
	jar cfe SpertaClient.jar client.SpertaClient -C $(BIN_DIR) client -C $(BIN_DIR) utils

jar: server-jar client-jar

# ------------------------------------------------------------------------------
# Execution Targets (Executable JAR Mode)
# ------------------------------------------------------------------------------

run-server-jar: server-jar
	$(JAVA) -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456

run-client-jar: client-jar
	$(JAVA) -jar SpertaClient.jar 127.0.0.1:22345 user1 1234

# ------------------------------------------------------------------------------
# Cleanup Targets
# ------------------------------------------------------------------------------

clean:
	-$(RM)
	-$(RM_FILES) SpertaServer.jar SpertaClient.jar