# Projeto 2 - SC 2025/2026
## Sistema Distribuído Sperta

### Autores

- Diogo Chambel - 53319
- Márcio Moreira - 41972
- Nuno Graxinha - 59855

### Desenvolvimento

O projeto foi desenvolvido em ambiente Windows, utilizando Java e JavaFX.

### Requisitos

- JDK com `java`, `javac` e `keytool` disponíveis.
- JavaFX 17 em `lib/javafx-sdk-17.0.21/lib`.
- `make` para utilizar os comandos do Makefile.

### Compilação

Na raiz da diretoria `Sperta/`:

```text
make
```

Para criar os JARs:

```text
make jar
```

Para compilar a aplicação gráfica:

```text
make gui
```

Para remover os ficheiros compilados e os JARs:

```text
make clean
```

### Execução

#### Servidor

O servidor utiliza, por omissão, o porto `22345`, a cifra `server-pw`, a keystore
`keystores/keystore.server` e a password `123456`:

```text
make run-server
```

Também pode ser iniciado através do JAR:

```text
make run-server-jar
```

Com parâmetros explícitos:

```text
java -cp bin server.SpertaServer <porto> <password-cifra> <caminho-keystore> <password-keystore-server>
java -jar SpertaServer.jar <porto> <password-cifra> <caminho-keystore> <password-keystore-server>
```

#### Cliente gráfico

```text
make run-gui
```

No ecrã de login, preencha o servidor, porto, username e password.
O botão **Create New Keystore / Truststore** regista um novo utilizador,
cria a keystore/truststore locais e envia o certificado do utilizador para
`data/certs/<username>.cert` no servidor.

#### Cliente de linha de comandos

```text
make run-client
make run-client2
make run-client3
```

Ou manualmente:

```text
java -cp bin client.SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>
java -jar SpertaClient.jar <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>
```

### Funcionalidades

Depois de autenticado, o cliente gráfico permite:

- Criar casas e descobrir apenas casas acessíveis ao utilizador.
- Registar dispositivos; os IDs são gerados automaticamente, por exemplo `M1`, `M2`.
- Conceder acesso a utilizadores por secção.
- Executar comandos EC com valores entre `0` e `600`.
- Consultar o estado dos dispositivos e o histórico RH.
- Criar e abrir relatórios RT.

As permissões são verificadas no servidor. O proprietário tem acesso a todas
as secções; outros utilizadores só têm acesso às secções que lhes foram
concedidas.

### Ficheiros gerados

- `keystores/users/keystore.<username>` - keystore do utilizador.
- `keystores/users/truststore.<username>` - truststore do utilizador.
- `data/certs/<username>.cert` - certificado do utilizador no servidor.
- `data/homes/` - casas cifradas e respetivos hashes.
- `data/keys/` - chaves de secção cifradas para cada utilizador.
- `RH/<house>_<device>_history.csv` - histórico de comandos do dispositivo.
- `RT/<user>_<house>_status.txt` - estado atual dos dispositivos.

O relatório RT tem o formato:

```text
User: user1, House: house1
M1: ON (2 min), 2026-11-05 16:05:00
```

O histórico RH tem cabeçalho CSV e regista também a transição para `0`
quando um temporizador termina:

```text
device,value,timestamp
M1,2,2026-11-05 16:05:00
M1,0,2026-11-05 16:07:00
```
