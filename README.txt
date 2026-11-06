PROJECT 2 - SC 2025/2026
========================
Sperta Distributed System

AUTHORS
-------
- Diogo Chambel - 53319
- Márcio Moreira - 41972
- Nuno Graxinha - 59855

DEVELOPMENT
-----------
The project was developed for Windows using Java and JavaFX.

REQUIREMENTS
------------
- A JDK with java, javac, and keytool available.
- JavaFX 17 in lib/javafx-sdk-17.0.21/lib.
- make for the Makefile commands.

The portable client launcher can run without a system Java installation when
the bundled runtime folder is present. The runtime folder is not tracked in
Git because the JDK is larger than GitHub's file-size limit.

COMPILATION
-----------
From the Sperta/ directory:

  make
  make jar
  make gui

To clean compiled files and JARs:

  make clean

RUNNING
-------

[ SERVER ]

The server uses port 22345, cipher password server-pw, server keystore
keystores/keystore.server, and keystore password 123456 by default:

  make run-server
  make run-server-jar

With explicit parameters:

Sample commands:

  java -cp bin server.SpertaServer <port> <cipher-password> <keystore-path> <server-keystore-password>
  java -jar SpertaServer.jar <port> <cipher-password> <keystore-path> <server-keystore-password>

Example with the default values:

  java -cp bin server.SpertaServer 22345 server-pw keystores/keystore.server 123456
  java -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456

Keep the server window open while clients are connected.

[ GRAPHICAL CLIENT ]

  make run-gui

Or, on a portable client computer:

  start-client.bat

Enter the server address, port, username, and password. The Create New
Keystore / Truststore button creates the local keystore and truststore and
uploads only the public certificate to data/certs/<username>.cert on the
server. The private key remains on the client computer.

[ COMMAND-LINE CLIENT ]

  make run-client
  make run-client2
  make run-client3

These targets use the same simple credentials flow as the graphical client.
The client derives the keystore password and resolves local keystore paths
automatically.

Or manually:

  java -cp bin client.SpertaClient <serverAddress> <user-id> <password>
  java -jar SpertaClient.jar <serverAddress> <user-id> <password>

Example:

  java -jar SpertaClient.jar 127.0.0.1:22345 user1 1234

FEATURES
--------
- Create houses and list only accessible houses.
- Register devices with automatic IDs such as M1 and M2.
- Grant section access to other users.
- Execute EC commands with values from 0 to 600.
- View device status and RH history.
- Create and open RT reports.

The owner can access every section. Other users can access only the sections
granted to them.

GENERATED FILES
---------------
- keystores/users/keystore.<username>
- keystores/users/truststore.<username>
- data/certs/<username>.cert
- data/homes/
- data/keys/
- RH/<house>_<device>_history.csv
- RT/<user>_<house>_status.txt

RT format:

  User: user1, House: house1
  M1: ON (2 min), 2026-11-05 16:05:00

RH format:

  device,value,timestamp
  M1,2,2026-11-05 16:05:00
  M1,0,2026-11-05 16:07:00

When a timer expires, the transition to value 0 is recorded.
