PROJETO 2 - SC 2025/2026
=========================
Sistema Distribuído Sperta

AUTORES
-------
- Diogo Chambel - 53319
- Márcio Moreira - 41972
- Nuno Graxinha - 59855

DESENVOLVIMENTO
---------------
O projeto foi desenvolvido em ambiente Windows, utilizando Java e JavaFX.

REQUISITOS
----------
- JDK com java, javac e keytool disponíveis.
- JavaFX 17 em lib/javafx-sdk-17.0.21/lib.
- make para utilizar os comandos do Makefile.

COMPILAÇÃO
----------
Na raiz da diretoria Sperta/:

  make
  make jar
  make gui

Para limpar os ficheiros compilados e os JARs:

  make clean

EXECUÇÃO
--------

[ SERVIDOR ]

O servidor utiliza, por omissão, o porto 22345, a cifra server-pw,
a keystore keystores/keystore.server e a password 123456:

  make run-server
  make run-server-jar

Com parâmetros explícitos:

  java -cp bin server.SpertaServer <porto> <password-cifra> <caminho-keystore> <password-keystore-server>
  java -jar SpertaServer.jar <porto> <password-cifra> <caminho-keystore> <password-keystore-server>

[ CLIENTE GRÁFICO ]

  make run-gui

No ecrã de login, preencha o servidor, porto, username e password.
O botão Create New Keystore / Truststore regista o utilizador, cria as
keystores/truststores locais e envia o certificado para
data/certs/<username>.cert no servidor.

[ CLIENTE DE LINHA DE COMANDOS ]

  make run-client
  make run-client2
  make run-client3

Ou manualmente:

  java -cp bin client.SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>
  java -jar SpertaClient.jar <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>

FUNCIONALIDADES
---------------
- Criar casas e listar apenas casas acessíveis.
- Registar dispositivos com IDs automáticos, como M1 e M2.
- Conceder acesso por secção a outros utilizadores.
- Executar EC com valores entre 0 e 600.
- Consultar estado dos dispositivos e histórico RH.
- Criar e abrir relatórios RT.

O proprietário tem acesso a todas as secções. Os restantes utilizadores só
acedem às secções que lhes foram concedidas.

FICHEIROS GERADOS
-----------------
- keystores/users/keystore.<username>
- keystores/users/truststore.<username>
- data/certs/<username>.cert
- data/homes/
- data/keys/
- RH/<house>_<device>_history.csv
- RT/<user>_<house>_status.txt

Formato RT:

  User: user1, House: house1
  M1: ON (2 min), 2026-11-05 16:05:00

Formato RH:

  device,value,timestamp
  M1,2,2026-11-05 16:05:00
  M1,0,2026-11-05 16:07:00

Quando um temporizador termina, é registada a transição para o valor 0.
