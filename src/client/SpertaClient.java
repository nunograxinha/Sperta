package client;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.HashMap;
import java.security.cert.Certificate;
import utils.CryptoService;

public class SpertaClient {

    public static void main(String[] args) {
        System.out.println("SpertaClient: main");
        SpertaClient client = new SpertaClient();
        client.startClient(args); // SpertaClient <serverAddress> <user-id> <password>
    }

    public void startClient(String[] args) {
        if (args.length != 7) {
            System.err.println(
                    "Usage: java SpertaClient <serverAddress> <truststore> <password-truststore> <keystore> <password-keystore> <user-id> <password>");
            return;
        }

        String serverAddressRaw = args[0];
        String truststorePath = args[1];
        String truststorePassword = args[2];
        String keystorePath = args[3];
        String keystorePassword = args[4];
        String username = args[5];
        String password = args[6];

        if (username.contains(":")) {
            System.err.println("Error: Username cannot contain the character ':'");
            return;
        }

        //Sockets SSL TLS, Keystrores e Truststores
        // Configurar truststore e keystore no sistema para usar TLS
        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);
        // Opcional: System.setProperty("javax.net.debug", "ssl");

        String serverAddress = serverAddressRaw;
        int port = 22345; // Default port

        if (serverAddressRaw.contains(":")) {
            String[] parts = serverAddressRaw.split(":");
            serverAddress = parts[0];
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number.");
                return;
            }
        }

        Scanner scanner = new Scanner(System.in);

        try {
            SSLSocketFactory sslFact = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) sslFact.createSocket(serverAddress, port);

            socket.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
            socket.startHandshake();

            try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                    ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

                System.out.println("Connected securely to server at " + serverAddress + ":" + port);

                // PASSO 1: Atestação
                if (!doAttestation(outStream, inStream)) {
                    return; // Atestação falhou — termina
                }

                // PASSO 2: Autenticação com retry
                if (!doAuth(outStream, inStream, username, password, scanner, keystorePath, keystorePassword)) {
                    return; // Autenticação falhou — termina
                }

                // PASSO 3: Menu e loop de comandos
                interactWithServer(outStream, inStream, scanner, username, keystorePath, keystorePassword);

            } finally {
                socket.close();
            }

        } catch (UnknownHostException e) {
            System.err.println("Server not found: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("I/O Error: " + e.getMessage());
        } catch (ClassNotFoundException e) {
            System.err.println("Class not found error: " + e.getMessage());
        }
    }

    private boolean doAttestation(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {

        // 1. Receber o nonce aleatório (8 bytes long) do Servidor
        long nonce = in.readLong();
        System.out.println("Recebido Nonce para atestação: " + nonce);

        byte[] calculatedHash;
        try {
            calculatedHash = calculateJarHashWithNonce(nonce);
        } catch (Exception e) {
            System.err.println("Erro no cálculo da hash local: " + e.getMessage());
            calculatedHash = new byte[0]; // array vazio sinaliza q falhou
        }

        // 2. Enviar a hash calculada de volta ao servidor
        out.writeObject(calculatedHash);
        out.flush();

        // 3. Aguardar resultado (OK ou NOK)
        String response = (String) in.readObject();

        if ("OK-ATTEST".equals(response)) {
            System.out.println("ATTESTATION OK");
            return true;
        } else {
            System.out.println("ATTESTATION FAILED: " + response);
            return false;
        }
    }

    private byte[] calculateJarHashWithNonce(long nonce) throws Exception {
        // Encontra o caminho a partir da execução onde estamos
        String jarPath = SpertaClient.class
            .getProtectionDomain()
            .getCodeSource()
            .getLocation()
            .toURI()
            .getPath();

        File jarFile = new File(jarPath);
        
        // Se o ProtectionDomain devolver a pasta bin/ (o que acontece quando se corre a partir
        // de código puro "make run-client"), forçamos o fallback para tentar achar o .jar gerado:
        if (jarFile.isDirectory()) {
             jarFile = new File("SpertaClient.jar");
             if (!jarFile.exists()) {
                 throw new Exception("Não encontrei o JAR em: " + jarFile.getAbsolutePath());
             }
        }

        if (!jarFile.exists() || !jarFile.isFile()) {
            throw new Exception("Ficheiro .jar não encontrado em " + jarFile.getAbsolutePath());
        }

        // Lê todo o ficheiro do cliente para a memória
        byte[] jarBytes = Files.readAllBytes(jarFile.toPath());

        // Põe o nonce de 8 bytes num array
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(nonce);
        byte[] nonceBytes = buffer.array();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // A regra é: concatenação do nonce com ficheiro executável.
        // Atualiza a digestão primeiro com o nonce, depois o jar
        digest.update(nonceBytes);
        digest.update(jarBytes);

        return digest.digest();
    }

    private boolean doAuth(ObjectOutputStream out, ObjectInputStream in,
            String username, String password, Scanner scanner,
            String keystorePath, String keystorePassword)
            throws IOException, ClassNotFoundException {

        while (true) {
            out.writeObject(username);
            out.writeObject(password);
            out.flush();

            // Lê resposta — pode ser Integer (0/1) ou String ("SEND-CERT")
            Object response = in.readObject();

            if (response instanceof String) {
                if ("SEND-CERT".equals(response)) {
                    // Utilizador novo — envia certificado
                    System.out.println("OK-NEW-USER");
                    sendCertificate(out, keystorePath, keystorePassword, username);
                    return true;
                }
            } else if (response instanceof Integer) {
                int authStatus = (Integer) response;
                if (authStatus == 1) {
                    System.out.println("OK-USER");
                    return true;
                } else {
                    System.out.println("WRONG-PWD");
                    System.out.print("Try again. Password: ");
                    password = scanner.nextLine().trim();
                }
            }
        }
    }

    private void sendCertificate(ObjectOutputStream out, String keystorePath,
            String keystorePassword, String username)
            throws IOException {
        try {
            // Carregar a keystore do utilizador
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
                ks.load(fis, keystorePassword.toCharArray());
            }

            // Obter o certificado — tenta pelo alias do username primeiro
            java.security.cert.Certificate cert = ks.getCertificate(username);
            if (cert == null) {
                // Tenta o primeiro alias disponível
                java.util.Enumeration<String> aliases = ks.aliases();
                if (aliases.hasMoreElements()) {
                    cert = ks.getCertificate(aliases.nextElement());
                }
            }

            if (cert == null) {
                System.err.println("Certificado não encontrado na keystore.");
                out.writeObject(new byte[0]);
            } else {
                out.writeObject(cert.getEncoded());
                System.out.println("Certificado enviado ao servidor.");
            }
            out.flush();

        } catch (Exception e) {
            System.err.println("Erro ao enviar certificado: " + e.getMessage());
            try {
                out.writeObject(new byte[0]);
                out.flush();
            } catch (Exception ignored) {
            }
        }
    }

    private void interactWithServer(ObjectOutputStream outStream, ObjectInputStream inStream, Scanner scanner, String username, String keystorePath, String keystorePassword) {
        System.out.println("\n╔═════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                          SMART HOME CONTROL PANEL                           ║");
        System.out.println("╠════════════════════╦════════════════════════════════════════════════════════╣");
        System.out.println("║ COMMAND            ║ DESCRIPTION                                            ║");
        System.out.println("╠════════════════════╬════════════════════════════════════════════════════════╣");
        System.out.printf("║ %-18s ║ %-54s ║\n", "CREATE <hm>", "Create a new house profile.");
        System.out.printf("║ %-18s ║ %-54s ║\n", "ADD <u1> <hm> <s>", "Add user <u1> to house <hm>, section <s>.");
        System.out.printf("║ %-18s ║ %-54s ║\n", "RD <hm> <s>", "Register a new device in a specific section.");
        System.out.printf("║ %-18s ║ %-54s ║\n", "EC <hm> <d> <v>", "Send state/timer value to the server.");
        System.out.printf("║ %-18s ║ %-54s ║\n", "RT <hm>", "Get the latest status of all devices in house.");
        System.out.printf("║ %-18s ║ %-54s ║\n", "RH <hm> <d>", "Retrieve device history logs (.csv).");
        System.out.println("╚════════════════════╩════════════════════════════════════════════════════════╝");
        System.out.println(" > Enter command or press Ctrl+C to exit.");
        try {
            while (true) {
                System.out.print("> ");
                if (!scanner.hasNextLine()) break;
                String line = scanner.nextLine().trim();
                if (line.isEmpty())
                    continue;

                String[] parts = line.split(" ");
                String command = parts[0].toUpperCase();

                // --- E2E: Validação e Cifra para o Comando EC ---
                if (command.equals("EC") && parts.length == 4) {
                    String hm = parts[1];
                    String d = parts[2];
                    String section = String.valueOf(d.charAt(0)).toUpperCase();
                    try {
                        int v = Integer.parseInt(parts[3]);
                        if (v < 0 || v > 600) {
                            System.out.println("Erro: O valor tem de estar entre 0 e 600.");
                            continue; // Aborta o envio e volta a pedir comando
                       }
                       
                        //Confidencialidade E2E EC
                        // 1. Pedir ao servidor a chave da secção
                        outStream.writeObject("GET_KEY " + hm + " " + section);
                        outStream.flush();

                        Object keyResp = inStream.readObject();
                        if (keyResp instanceof byte[]) {
                            // 2. Extrair chave privada local para desempacotar a chave AES
                            java.security.PrivateKey privKey = loadPrivateKeyForUser(username, keystorePath, keystorePassword);
                            SecretKey aesKey = CryptoService.unwrapKeyRSA((byte[]) keyResp, privKey);

                            // 3. Cifrar o valor numérico com AES-128 e codificar para Base64
                            byte[] encVal = CryptoService.encryptAES(String.valueOf(v), aesKey);
                            String newValBase64 = java.util.Base64.getEncoder().encodeToString(encVal);

                            // 4. Substituir a linha original pela linha cifrada
                            line = "EC " + hm + " " + d + " " + newValBase64;
                            parts = line.split(" ");
                        } else {
                            System.out.println("Erro E2E: Falha ao obter a chave de secção. Servidor diz: " + keyResp);
                            continue; // Aborta o envio
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("Erro: Comando EC requer um valor numérico inteiro.");
                        continue;
                    } catch (Exception e) {
                        System.out.println("Erro E2E: " + e.getMessage());
                        continue;
                    }
                }

                // Envia o comando ao servidor
                outStream.writeObject(line);
                
                // --- E2E: Injeção de chaves no comando CREATE ---
                if (command.equals("CREATE") && parts.length >= 2) {
                    try {
                        HashMap<String, byte[]> wrappedKeys = generateAndWrapSectionKeys(username, keystorePath, keystorePassword);
                        outStream.writeObject(wrappedKeys);
                    } catch (Exception e) {
                        System.err.println("Erro a gerar chaves: " + e.getMessage());
                        outStream.writeObject(new HashMap<String, byte[]>()); // fallback vazio
                    }
                }
                
                outStream.flush();

                // RT e RH recebem ficheiro — os outros recebem String simples ou objetos complexos (E2E)
                if (command.equals("RT")) {
                    receiveFile(inStream, buildRTFilename(parts), username, keystorePath, keystorePassword);
                } else if (command.equals("RH")) {
                    receiveFile(inStream, buildRHFilename(parts), username, keystorePath, keystorePassword);
                } else if (command.equals("ADD") && parts.length >= 4) {
                    // ADD recebe um Object[] primeiro em caso de sucesso (E2E), 
                    // processa, devolve o array HashMap, e depois recebe a String final.
                    // Em caso de erro, recebe direto uma String
                    Object resp = inStream.readObject();
                    if (resp instanceof Object[]) {
                        Object[] e2eData = (Object[]) resp;
                        if ("E2E_ADD".equals(e2eData[0])) {
                            HashMap<String, byte[]> keysToWrap = (HashMap<String, byte[]>) e2eData[1];
                            byte[] targetCertBytes = (byte[]) e2eData[2];
                            
                            try {
                                // 1. Converter bytes recebidos num objeto de Certificado
                                java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
                                java.security.cert.Certificate targetCert = certFactory.generateCertificate(new java.io.ByteArrayInputStream(targetCertBytes));
                                
                                // 2. Obter o caminho e a password da Truststore que foi usada no arranque deste cliente
                                String currentTrustStorePath = System.getProperty("javax.net.ssl.trustStore");
                                String currentTrustStorePass = System.getProperty("javax.net.ssl.trustStorePassword");
                                
                                // 3. Carregar o ficheiro (ex: truststore.user1)
                                java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
                                try (java.io.FileInputStream fis = new java.io.FileInputStream(currentTrustStorePath)) {
                                    ts.load(fis, currentTrustStorePass.toCharArray());
                                }
                                
                                // 4. Adicionar o novo certificado à lista de confiança (ex: alias "user2")
                                String targetUser = parts[1]; 
                                ts.setCertificateEntry(targetUser, targetCert);
                                
                                // 5. Gravar as alterações de volta no ficheiro físico no disco
                                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(currentTrustStorePath)) {
                                    ts.store(fos, currentTrustStorePass.toCharArray());
                                }
                                System.out.println("[TRUST] Certificado de " + targetUser + " guardado na truststore: " + currentTrustStorePath);
                                
                            } catch (Exception e) {
                                System.err.println("[TRUST] Erro ao atualizar truststore local: " + e.getMessage());
                            }

                            try {
                                HashMap<String, byte[]> newWrappedKeys = rewrapSectionKeys(keysToWrap, targetCertBytes, username, keystorePath, keystorePassword);
                                outStream.writeObject(newWrappedKeys);
                                outStream.flush();
                                
                                String finalResp = (String) inStream.readObject();
                                System.out.println("[SERVER]: " + finalResp);
                            } catch (Exception e) {
                                System.err.println("Falha a desembrulhar chaves: " + e.getMessage());
                                outStream.writeObject(new HashMap<String, byte[]>()); // fallback
                            }
                        }
                    } else if (resp instanceof String) {
                        System.out.println("[SERVER]: " + (String) resp);
                    }
                } else {
                    String response = (String) inStream.readObject();
                    System.out.println("[SERVER]: " + response);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String resolveKeystoreAlias(java.security.KeyStore ks, String username) throws Exception {
        if (ks.containsAlias(username)) {
            return username;
        }

        java.util.Enumeration<String> aliases = ks.aliases();
        if (aliases.hasMoreElements()) {
            return aliases.nextElement();
        }

        throw new Exception("Nenhum alias válido encontrado na keystore.");
    }

    private java.security.PrivateKey loadPrivateKeyForUser(String username, String ksPath, String ksPass) throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(ksPath)) {
            ks.load(fis, ksPass.toCharArray());
        }

        String usedAlias = resolveKeystoreAlias(ks, username);
        return CryptoService.loadPrivateKey(ksPath, ksPass.toCharArray(), usedAlias);
    }

    private HashMap<String, byte[]> generateAndWrapSectionKeys(String username, String ksPath, String ksPass) throws Exception {
        HashMap<String, byte[]> map = new HashMap<>();

        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(ksPath)) {
            ks.load(fis, ksPass.toCharArray());
        }

        Certificate cert = ks.getCertificate(username);
        if (cert == null) {
            cert = ks.getCertificate(resolveKeystoreAlias(ks, username));
        }
        if (cert == null) {
            throw new Exception("Certificado não encontrado na keystore.");
        }

        java.security.PublicKey pubKey = CryptoService.getPublicKeyFromCertBytes(cert.getEncoded());

        String[] sections = {"E", "G", "L", "M", "P", "S"};
        for (String s : sections) {
            SecretKey aesKey = CryptoService.generateAESKey();
            byte[] wrappedKey = CryptoService.wrapKeyRSA(aesKey, pubKey);
            map.put(s, wrappedKey);
        }
        return map;
    }

    private HashMap<String, byte[]> rewrapSectionKeys(HashMap<String, byte[]> keysToWrap, byte[] targetCertBytes, String username, String ksPath, String ksPass) throws Exception {
        HashMap<String, byte[]> newWrappedKeys = new HashMap<>();

        java.security.PrivateKey privKey = loadPrivateKeyForUser(username, ksPath, ksPass);
        java.security.PublicKey targetPubKey = CryptoService.getPublicKeyFromCertBytes(targetCertBytes);

        for (java.util.Map.Entry<String, byte[]> entry : keysToWrap.entrySet()) {
            SecretKey rawKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
            byte[] newWrappedBytes = CryptoService.wrapKeyRSA(rawKey, targetPubKey);
            newWrappedKeys.put(entry.getKey(), newWrappedBytes);
        }

        return newWrappedKeys;
    }


    //obtençao de informações cifradas
    private void receiveFile(ObjectInputStream in, String localFilename, String username, String ksPath, String ksPass)
            throws Exception {

        Object responseObj = in.readObject();
        String responseStatus = null;
        HashMap<String, byte[]> wrappedKeysMap = null;

        if (responseObj instanceof String) {
            responseStatus = (String) responseObj;
        } else if (responseObj instanceof Object[]) {
            Object[] data = (Object[]) responseObj;
            responseStatus = (String) data[0];
            wrappedKeysMap = (HashMap<String, byte[]>) data[1];
        }

        if (!"OK".equals(responseStatus)) {
            System.out.println("[SERVER]: " + responseStatus);
            return;
        }

        // Recebe tamanho e bytes
        long fileSize = (Long) in.readObject();
        byte[] data = new byte[(int) fileSize];

        // Lê todos os bytes
        int totalRead = 0;
        while (totalRead < fileSize) {
            int read = in.read(data, totalRead, (int) (fileSize - totalRead));
            if (read == -1)
                break;
            totalRead += read;
        }

        String contentStr = new String(data, "UTF-8");

        // === E2E DESCIFRAR ===
        // 1. Extrair chave privada do cliente
        java.security.PrivateKey privKey = loadPrivateKeyForUser(username, ksPath, ksPass);

        // 2. Desembrulhar as chaves AES para uso real
        HashMap<String, SecretKey> aesKeys = new HashMap<>();
        if (wrappedKeysMap != null) {
            for (java.util.Map.Entry<String, byte[]> entry : wrappedKeysMap.entrySet()) {
                try {
                    SecretKey aesKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
                    aesKeys.put(entry.getKey(), aesKey);
                } catch (Exception e) {
                    System.err.println("Falha ao desembrulhar chave da secção " + entry.getKey() + ": " + e.getMessage());
                }
            }
        }

        // 3. Substituir os valores cifrados no texto por texto claro
        StringBuilder decryptedContent = new StringBuilder();
        Scanner sc = new Scanner(contentStr);

        while (sc.hasNextLine()) {
            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;

            // RH tem vírgulas; processa primeiro para evitar confundir timestamps com RT
            if (line.contains(",")) {
                String[] parts = line.split(",");
                if (parts.length >= 3 && !line.startsWith("device,value")) {
                    String devId = parts[0];
                    String encryptedVal = parts[1].trim();
                    String sec = String.valueOf(devId.charAt(0)).toUpperCase();
                    SecretKey k = aesKeys.get(sec);

                    if (k != null && isBase64(encryptedVal)) {
                        try {
                            byte[] dec = java.util.Base64.getDecoder().decode(encryptedVal);
                            String decodedValue = CryptoService.decryptAES(dec, k);
                            parts[1] = decodedValue;
                            decryptedContent.append(String.join(",", parts)).append("\n");
                        } catch (Exception e) {
                            decryptedContent.append(line).append("\n");
                        }
                    } else {
                        decryptedContent.append(line).append("\n");
                    }
                } else {
                    decryptedContent.append(line).append("\n");
                }
            } else if (line.contains(":")) {
                String[] parts = line.split(":");
                if (parts.length >= 2) {
                    String devId = parts[0];
                    String encryptedVal = parts[1].trim();
                    String sec = String.valueOf(devId.charAt(0)).toUpperCase();
                    SecretKey k = aesKeys.get(sec);
                    if (k != null && isBase64(encryptedVal)) {
                        try {
                            byte[] dec = java.util.Base64.getDecoder().decode(encryptedVal);
                            String decodedValue = CryptoService.decryptAES(dec, k);
                            decryptedContent.append(devId).append(":").append(decodedValue).append("\n");
                        } catch (Exception e) {
                            decryptedContent.append(line).append("\n");
                        }
                    } else {
                        decryptedContent.append(line).append("\n");
                    }
                } else {
                    decryptedContent.append(line).append("\n");
                }
            } else {
                decryptedContent.append(line).append("\n");
            }
        }
        sc.close();

        // Guarda o ficheiro (decifrado) localmente
        byte[] finalDecBytes = decryptedContent.toString().getBytes("UTF-8");
        Files.write(Paths.get(localFilename), finalDecBytes);

        System.out.println("Ficheiro guardado: " + localFilename);
        System.out.println("--- Conteúdo ---");
        System.out.println(decryptedContent.toString());
        System.out.println("----------------");
    }

    private boolean isBase64(String s) {
        try {
            java.util.Base64.getDecoder().decode(s);
            return true;
        } catch(Exception e) {
            return false;
        }
    }

    private String buildRTFilename(String[] parts) {
        String house = parts.length >= 2 ? parts[1] : "house";
        return "rt_" + house + ".txt";
    }

    private String buildRHFilename(String[] parts) {
        String house = parts.length >= 2 ? parts[1] : "house";
        String device = parts.length >= 3 ? parts[2] : "device";
        return "rh_" + house + "_" + device + ".csv";
    }
}