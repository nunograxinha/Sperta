# Project 2 - SC 2025/2026
## Sperta Distributed System

### Authors

- Diogo Chambel - 53319
- Márcio Moreira - 41972
- Nuno Graxinha - 59855

### Development

The project was developed for Windows using Java and JavaFX.

### Requirements

- A JDK with `java`, `javac`, and `keytool` available.
- JavaFX 17 in `lib/javafx-sdk-17.0.21/lib`.
- `make` for the Makefile commands.

The portable client launcher can run without a system Java installation when the
bundled `runtime` folder is present. The `runtime` folder is intentionally not
tracked in Git because the JDK is larger than GitHub's file-size limit.

### Compilation

From the `Sperta/` directory:

```text
make
```

To create the JAR files:

```text
make jar
```

To compile the graphical application:

```text
make gui
```

To remove compiled files and JARs:

```text
make clean
```

### Running

#### Server

By default, the server uses port `22345`, cipher password `server-pw`, server
keystore `keystores/keystore.server`, and keystore password `123456`:

```text
make run-server
```

It can also be started from the JAR:

```text
make run-server-jar
```

With explicit parameters:

Sample commands:

```text
java -cp bin server.SpertaServer <port> <cipher-password> <keystore-path> <server-keystore-password>
java -jar SpertaServer.jar <port> <cipher-password> <keystore-path> <server-keystore-password>
```

Example with the default values:

```text
java -cp bin server.SpertaServer 22345 server-pw keystores/keystore.server 123456
java -jar SpertaServer.jar 22345 server-pw keystores/keystore.server 123456
```

Keep the server window open while clients are connected. The server must be
listening on port `22345` before the client tries to connect.

#### Graphical client

```text
make run-gui
```

Or, on a portable client computer:

```text
start-client.bat
```

At the login screen, enter the server address, port, username, and password.
The **Create New Keystore / Truststore** button creates the local keystore and
truststore. It also uploads only the public certificate to
`data/certs/<username>.cert` on the server. The private key remains on the
client computer.

#### Command-line client

```text
make run-client
make run-client2
make run-client3
```

These targets use the same simple credentials flow as the graphical client.
The client derives the keystore password and resolves the local keystore
paths automatically.

Or manually:

```text
java -cp bin client.SpertaClient <serverAddress> <user-id> <password>
java -jar SpertaClient.jar <serverAddress> <user-id> <password>
```

The legacy form with explicit keystore paths is also supported:

```text
java -cp bin client.SpertaClient <serverAddress> <truststore> <truststore-password> <keystore> <keystore-password> <user-id> <password>
java -jar SpertaClient.jar <serverAddress> <truststore> <truststore-password> <keystore> <keystore-password> <user-id> <password>
```

Example:

```text
java -jar SpertaClient.jar 127.0.0.1:22345 user1 1234
```

### Features

After authentication, the graphical client allows users to:

- Create houses and discover only houses they can access.
- Register devices with automatically generated IDs such as `M1` and `M2`.
- Grant section access to other users.
- Execute EC commands with values from `0` to `600`.
- View device status and RH history.
- Create and open RT reports.

Permissions are enforced by the server. The owner can access every section;
other users can access only the sections granted to them.

### Generated files

- `keystores/users/keystore.<username>` - the user's private key and certificate.
- `keystores/users/truststore.<username>` - the server truststore.
- `data/certs/<username>.cert` - the user's public certificate on the server.
- `data/homes/` - encrypted houses and their integrity hashes.
- `data/keys/` - encrypted section keys for each user.
- `RH/<house>_<device>_history.csv` - device command history.
- `RT/<user>_<house>_status.txt` - current device status.

The RT report format is:

```text
User: user1, House: house1
M1: ON (2 min), 2026-11-05 16:05:00
```

The RH history has a CSV header and also records the transition to `0` when a
timer expires:

```text
device,value,timestamp
M1,2,2026-11-05 16:05:00
M1,0,2026-11-05 16:07:00
```
