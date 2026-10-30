package server;

import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class SpertaServer {
    
    //gestao de concorrencia
    private static final ConcurrentHashMap<String, ReentrantReadWriteLock> fileLocks = new ConcurrentHashMap<>();
    private static String cipherPassword;
    private static byte[] pbeSalt;

    private static ReentrantReadWriteLock getLock(String filename) {
        return fileLocks.computeIfAbsent(filename, k -> new ReentrantReadWriteLock());
    }

    private static void initPBE(String password) throws Exception {
        cipherPassword = password;
        File saltFile = new File("data/server_salt.bin");
        if (saltFile.exists()) {
            pbeSalt = Files.readAllBytes(saltFile.toPath());
        } else {
            saltFile.getParentFile().mkdirs();
            pbeSalt = new byte[16];
            new SecureRandom().nextBytes(pbeSalt);
            Files.write(saltFile.toPath(), pbeSalt);
        }
    }

    public static byte[] lerFicheiroCifrado(String caminho) throws Exception {
        File f = new File(caminho);
        if (!f.exists() || f.length() == 0) return null;
        
        byte[] fileData = Files.readAllBytes(Paths.get(caminho));
        
        // PBEWithHmacSHA256AndAES_128 requires IV. We store/read the IV appended to the file.
        // We will assume the first 16 bytes is the IV
        if (fileData.length < 16) return null; // Too short to even have an IV
        
        byte[] iv = new byte[16];
        System.arraycopy(fileData, 0, iv, 0, 16);
        byte[] actualData = new byte[fileData.length - 16];
        System.arraycopy(fileData, 16, actualData, 0, actualData.length);

        PBEKeySpec keySpec = new PBEKeySpec(cipherPassword.toCharArray());
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey key = kf.generateSecret(keySpec);
        
        // Setup parameters using IV and salt
        javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
        PBEParameterSpec paramSpec = new PBEParameterSpec(pbeSalt, 100, ivSpec);

        Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        c.init(Cipher.DECRYPT_MODE, key, paramSpec);
        return c.doFinal(actualData);
    }

    //servidor cifra os ficheiros
    public static void escreverFicheiroCifrado(String caminho, byte[] textoLimpo) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(cipherPassword.toCharArray());
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey key = kf.generateSecret(keySpec);
        
        // Generate a random IV for every file write
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
        PBEParameterSpec paramSpec = new PBEParameterSpec(pbeSalt, 100, ivSpec);

        Cipher c = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        c.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        byte[] cifrado = c.doFinal(textoLimpo);
        
        // Prepend IV to the encrypted data
        byte[] finalFileData = new byte[16 + cifrado.length];
        System.arraycopy(iv, 0, finalFileData, 0, 16);
        System.arraycopy(cifrado, 0, finalFileData, 16, cifrado.length);
        
        File f = new File(caminho);
        if (!f.getParentFile().exists()) f.getParentFile().mkdirs();
        
        Files.write(Paths.get(caminho), finalFileData);
    }

    public static void main(String[] args) {
        System.out.println("SpertaServer: main");
        SpertaServer server = new SpertaServer();
        server.startServer(args);
    }

    public void startServer(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: java SpertaServer <port> <password-cifra> <keystore> <password-keystore>");
            System.exit(1);
        }

        int port = 22345;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println("Invalid argument: port must be an integer.");
            System.exit(1);
        }

        String cipherPassword = args[1];
        String keystorePath = args[2];
        String keystorePassword = args[3];

        try {
            initPBE(cipherPassword);
        } catch (Exception e) {
            System.err.println("Failed to initialize PBE engine: " + e.getMessage());
            System.exit(1);
        }

        //Socket SSL TLS, Keystrores e Truststores
        // Configurar as propriedades de sistema para o SSL/TLS
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);
        // Opcional: Se ver detalhes do handshake SSL (para debug), descomentar
        // a linha abaixo:
        // System.setProperty("javax.net.debug", "ssl");

        String referenceClientPath = loadExpectedClientPath();
        if (referenceClientPath == null) {
            System.out.println("WARNING: attestation.txt não encontrado. Atestação desativada.");
        } else {
            System.out.println("Atestação ativa com jar de referência: " + referenceClientPath);
        }

        //Socket SSL TLS
        try {
            SSLServerSocketFactory sslSrvFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket sSoc = (SSLServerSocket) sslSrvFact.createServerSocket(port);

            sSoc.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });

            System.out.println("Server started on port " + port + " (TLS)");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) sSoc.accept();
                System.out.println("New secured client connected: " + clientSocket.getInetAddress());
                ServerThread newServerThread = new ServerThread(clientSocket, referenceClientPath);
                newServerThread.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String loadExpectedClientPath() {
        File file = new File("data/attestation.txt");
        if (!file.exists())
            return null;

        try (Scanner sc = new Scanner(file)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine().trim();
                // O texto a procurar muda para o novo formato ("SpertaClient:/path/...")
                if (line.startsWith("SpertaClient:")) {
                    return line.substring("SpertaClient:".length()).trim();
                }
            }
        } catch (Exception e) {
            System.err.println("Erro a ler attestation.txt: " + e.getMessage());
        }
        return null;
    }

    class ServerThread extends Thread {
        private SSLSocket socket = null;
        private final String referenceClientPath;

        ServerThread(SSLSocket inSocket, String referenceClientPath) {
            this.socket = inSocket;
            this.referenceClientPath = referenceClientPath;
        }

        public void run() {
            ObjectInputStream inStream = null;
            ObjectOutputStream outStream = null;

            try {
                outStream = new ObjectOutputStream(socket.getOutputStream());
                inStream = new ObjectInputStream(socket.getInputStream());

                // PASSO 1: Atestação
                if (referenceClientPath != null && !handleAttestation(inStream, outStream)) {
                    socket.close();
                    return;
                }

                // PASSO 2: Autenticação com retry
                // *** LOOP — continua até autenticar com sucesso ***
                String username = null;
                while (true) {
                    String user = (String) inStream.readObject();
                    String pass = (String) inStream.readObject();
                    System.out.println("Received credentials from: " + user);

                    int authResult = authenticateUser(user, pass, inStream, outStream);

                    if (authResult == 0) {
                        // WRONG-PWD — envia resposta e continua o loop
                        outStream.writeObject(Integer.valueOf(0));
                        outStream.flush();
                        System.out.println("WRONG-PWD: " + user);

                    } else if (authResult == 1) {
                        // OK-USER
                        outStream.writeObject(Integer.valueOf(1));
                        outStream.flush();
                        System.out.println("OK-USER: " + user);
                        username = user;
                        break;

                    } else if (authResult == 2) {
                        // OK-NEW-USER — certificado já foi tratado dentro do authenticateUser
                        System.out.println("OK-NEW-USER: " + user);
                        username = user;
                        break;
                    }
                }

                // PASSO 3: Receber comandos
                receiveMessages(inStream, outStream, username);

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private boolean handleAttestation(ObjectInputStream in, ObjectOutputStream out)
                throws IOException {

            // 1. Gerar e enviar o nonce (8 bytes)
            SecureRandom random = new SecureRandom();
            long nonce = random.nextLong();
            out.writeLong(nonce);
            out.flush();

            try {
                // 2. Receber a hash do cliente
                byte[] clientHash = (byte[]) in.readObject();

                // 3. Ler cópia de referência do Jar localmente TODO mudar o caminho do file no
                // attestation.txt para o Jar
                File referenceFile = new File(referenceClientPath);
                if (!referenceFile.exists()) {
                    System.err.println("Ficheiro de referência do cliente não encontrado: " + referenceClientPath);
                    out.writeObject("NOK-ATTEST");
                    out.flush();
                    return false;
                }
                byte[] referenceJarBytes = Files.readAllBytes(referenceFile.toPath());

                // 4. Calcular a hash local com o mesmo nonce
                ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
                buffer.putLong(nonce);
                byte[] nonceBytes = buffer.array();

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(nonceBytes);
                digest.update(referenceJarBytes);
                byte[] serverHash = digest.digest();

                // 5. Comparar
                if (Arrays.equals(clientHash, serverHash)) {
                    out.writeObject("OK-ATTEST");
                    out.flush();
                    System.out.println("Attestation OK (Nonce-based SHA-256 matched)");
                    return true;
                } else {
                    out.writeObject("NOK-ATTEST");
                    out.flush();
                    System.out.println("Attestation FAILED: Hashes do not match");
                    return false;
                }
            } catch (Exception e) {
                e.printStackTrace();
                try {
                    out.writeObject("NOK-ATTEST");
                    out.flush();
                } catch (Exception ignores) {
                }
                return false;
            }
        }

        private void receiveMessages(ObjectInputStream inStream, ObjectOutputStream outStream,
                String username) {
            try {
                while (true) {
                    String msg = (String) inStream.readObject();
                    System.out.println("Received from " + username + ": " + msg);

                    String[] parts = msg.split(" ");
                    String command = parts[0].toUpperCase();
                    String response = "Invalid command";

                    if (command.equals("CREATE")) {
                        if (parts.length >= 2) {
                            java.util.HashMap<String, byte[]> keys = new java.util.HashMap<>();
                            try {
                                keys = (java.util.HashMap<String, byte[]>) inStream.readObject();
                            } catch (Exception e) {
                                System.err.println("Erro ao receber chaves de secção: " + e.getMessage());
                            }
                            response = createHouse(parts[1], username, keys);
                        } else {
                            response = "Invalid CREATE command format.";
                        }
                        outStream.writeObject(response);
                        outStream.flush();

                    } else if (command.equals("RD")) {
                        if (parts.length >= 3) {
                            response = registerDevice(parts[1], parts[2], username);
                        } else {
                            response = "Invalid RD command format.";
                        }
                        outStream.writeObject(response);
                        outStream.flush();

                    } else if (command.equals("ADD")) {
                        if (parts.length >= 4) {
                            String targetUser = parts[1];
                            String houseName = parts[2];
                            String section = parts[3];
                            response = addPermission(targetUser, houseName, section, username);
                            
                            if (response.equals("OK")) {
                                try {
                                    // 1. Ler o certificado do utilizador alvo
                                    File certFile = new File("data/certs/" + targetUser + ".cert");
                                    byte[] targetCertBytes = null;
                                    if (certFile.exists()) {
                                        targetCertBytes = Files.readAllBytes(certFile.toPath());
                                    }
                                    
                                    // 2. Ler as chaves da secção pedidas cifradas pela chave do cur User
                                    java.util.HashMap<String, byte[]> keysToWrap = new java.util.HashMap<>();
                                    if (section.equalsIgnoreCase("all")) {
                                        String[] secs = {"E", "G", "L", "M", "P", "S"};
                                        for (String s : secs) {
                                            File kf = new File("data/keys/key." + houseName + "." + s + "." + username);
                                            if (kf.exists()) keysToWrap.put(s, Files.readAllBytes(kf.toPath()));
                                        }
                                    } else {
                                        File kf = new File("data/keys/key." + houseName + "." + section.toUpperCase() + "." + username);
                                        if (kf.exists()) keysToWrap.put(section.toUpperCase(), Files.readAllBytes(kf.toPath()));
                                    }
                                    
                                    // 3. Enviar para o cliente descodificar e voltar a embrulhar
                                    Object[] e2eData = new Object[]{"E2E_ADD", keysToWrap, targetCertBytes};
                                    outStream.writeObject(e2eData);
                                    outStream.flush();
                                    
                                    // 4. Receber as novas chaves
                                    Object resp = inStream.readObject();
                                    if (resp instanceof java.util.HashMap) {
                                        java.util.HashMap<String, byte[]> newKeys = (java.util.HashMap<String, byte[]>) resp;
                                        for (java.util.Map.Entry<String, byte[]> entry : newKeys.entrySet()) {
                                            String s = entry.getKey();
                                            String outPath = "data/keys/key." + houseName + "." + s + "." + targetUser;
                                            Files.write(Paths.get(outPath), entry.getValue());
                                        }
                                        response = "OK - Target user " + targetUser + " now has section key(s).";
                                    } else {
                                        response = "NOK - Falha ao receber as chaves renvolvidas (E2E).";
                                    }
                                    
                                } catch (Exception e) {
                                    System.err.println("Erro no E2E_ADD: " + e.getMessage());
                                    response = "NOK - Erro interno no E2E_ADD.";
                                }
                            }
                            
                            outStream.writeObject(response);
                            outStream.flush();

                        } else {
                            response = "Invalid ADD command format.";
                            outStream.writeObject(response);
                            outStream.flush();
                        }

                    } else if (command.equals("GET_KEY")) {
                        // Formato: GET_KEY <hm> <sec>
                        if (parts.length >= 3) {
                            String houseName = parts[1];
                            String section = parts[2].toUpperCase();
                            File kf = new File("data/keys/key." + houseName + "." + section + "." + username);
                            if (kf.exists()) {
                                byte[] keyBytes = java.nio.file.Files.readAllBytes(kf.toPath());
                                outStream.writeObject(keyBytes);
                            } else {
                                outStream.writeObject("NO_KEY");
                            }
                        } else {
                            outStream.writeObject("INVALID_FORMAT");
                        }
                        outStream.flush();

                    } else if (command.equals("EC")) {
                        if (parts.length >= 4) {
                            response = executeCommand(parts[1], parts[2], parts[3], username);
                        } else {
                            response = "Invalid EC command format.";
                        }
                        outStream.writeObject(response);
                        outStream.flush();

                    } else if (command.equals("RT")) {
                        // RT não envia String simples — tem método próprio
                        if (parts.length >= 2) {
                            handleRT(parts[1], username, outStream);
                        } else {
                            outStream.writeObject("NOK");
                            outStream.flush();
                        }

                    } else if (command.equals("RH")) {
                        // RH não envia String simples — tem método próprio
                        if (parts.length >= 3) {
                            handleRH(parts[1], parts[2], username, outStream);
                        } else {
                            outStream.writeObject("NOK");
                            outStream.flush();
                        }

                    } else {
                        outStream.writeObject(response);
                        outStream.flush();
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Client " + username + " disconnected.");
            }
        }

        private void handleRT(String houseName, String username, ObjectOutputStream outStream)
                throws IOException {

            String housePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(housePath);

            Lock readLock = getLock(housePath).readLock();
            readLock.lock();
            try {
                if (!houseFile.exists()) {
                    outStream.writeObject("NOHM");
                    outStream.flush();
                    return;
                }

                // verificar antes de ler ***
                if (!verifyFileHash(housePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                StringBuilder content = new StringBuilder();
                boolean hasPermission = false;
                java.util.List<String> accessibleSections = new java.util.ArrayList<>();

                try {
                    byte[] decBytes = lerFicheiroCifrado(housePath);
                    try (Scanner sc = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        // Primeira linha é o dono
                        String owner = sc.hasNextLine() ? sc.nextLine().trim() : "";

                        if (owner.equals(username)) {
                            hasPermission = true;
                        }

                        // Ler cada secção
                        while (sc.hasNextLine()) {
                            String line = sc.nextLine().trim();
                            if (line.isEmpty())
                                continue;

                            // Verificar se o utilizador tem permissão nesta secção
                            boolean canAccessSection = owner.equals(username);
                            if (!canAccessSection) {
                                int bracketStart = line.lastIndexOf('[');
                                int bracketEnd = line.lastIndexOf(']');
                                if (bracketStart != -1 && bracketEnd > bracketStart) {
                                    String users = line.substring(bracketStart + 1, bracketEnd);
                                    for (String u : users.split(",")) {
                                        if (u.trim().equals(username)) {
                                            canAccessSection = true;
                                            hasPermission = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (!canAccessSection)
                                continue;
                                
                            // O utilizador tem permissão, guarda a secção para lhe devolvermos a chave depois
                            String secName = line.substring(0, line.indexOf(':'));
                            if (!accessibleSections.contains(secName)) {
                                accessibleSections.add(secName);
                            }

                            // Extrair dispositivos e valores
                            int parenStart = line.indexOf('(');
                            int parenEnd = line.indexOf(')');
                            if (parenStart == -1 || parenEnd <= parenStart)
                                continue;

                            String devicesStr = line.substring(parenStart + 1, parenEnd).trim();
                            if (devicesStr.isEmpty())
                                continue;

                            // Cada dispositivo
                            for (String dev : devicesStr.split(",")) {
                                dev = dev.trim();
                                if (dev.contains("-")) {
                                    String[] devParts = dev.split("-");
                                    String deviceId = devParts[0];
                                    String value = devParts[1];
                                    String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
                                    File logFile = new File(
                                            "data/logs/" + houseName + "/" + section + "/" + deviceId + ".csv");
                                    if (!logFile.exists())
                                        continue;

                                    content.append(deviceId).append(":").append(value).append("\n");
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    outStream.writeObject("NOK");
                    outStream.flush();
                    return;
                }

                if (!hasPermission) {
                    outStream.writeObject("NOPERM");
                    outStream.flush();
                    return;
                }

                if (content.length() == 0) {
                    outStream.writeObject("NODATA");
                    outStream.flush();
                    return;
                }

                // E2E: Obter as chaves das secções às quais o utilizador teve acesso
                java.util.HashMap<String, byte[]> keysMap = new java.util.HashMap<>();
                for (String s : accessibleSections) {
                    File kf = new File("data/keys/key." + houseName + "." + s + "." + username);
                    if (kf.exists()) keysMap.put(s, Files.readAllBytes(kf.toPath()));
                }

                // Enviar OK + Chaves + tamanho + bytes
                byte[] data = content.toString().getBytes("UTF-8");
                outStream.writeObject(new Object[]{"OK", keysMap});
                outStream.writeObject((long) data.length);
                outStream.write(data);
                outStream.flush();

                System.out.println("RT sent to " + username + ": " + data.length + " bytes");
            } finally {
                readLock.unlock();
            }
        }

        private void handleRH(String houseName, String deviceId, String username,
                ObjectOutputStream outStream) throws IOException {

            String housePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(housePath);

            Lock houseReadLock = getLock(housePath).readLock();
            houseReadLock.lock();

            try {
                // Verificar se a casa existe
                if (!houseFile.exists()) {
                    outStream.writeObject("NOHM");
                    outStream.flush();
                    return;
                }

                // verificar antes de ler a casa
                if (!verifyFileHash(housePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                // Verificar se o dispositivo existe e se o utilizador tem permissao
                boolean deviceFound = false;
                boolean hasPermission = false;

                try {
                    byte[] decBytes = lerFicheiroCifrado(housePath);
                    try (Scanner sc = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        String owner = sc.hasNextLine() ? sc.nextLine().trim() : "";

                        if (owner.equals(username)) {
                            hasPermission = true;
                        }

                        while (sc.hasNextLine()) {
                            String line = sc.nextLine().trim();
                            if (line.isEmpty())
                                continue;

                            int parenStart = line.indexOf('(');
                            int parenEnd = line.indexOf(')');
                            if (parenStart == -1 || parenEnd <= parenStart)
                                continue;

                            String devicesStr = line.substring(parenStart + 1, parenEnd).trim();
                            if (devicesStr.isEmpty())
                                continue;

                            for (String dev : devicesStr.split(",")) {
                                dev = dev.trim();
                                String devId = dev.contains("-") ? dev.split("-")[0] : dev;
                                if (devId.equals(deviceId)) {
                                    deviceFound = true;

                                    if (!hasPermission) {
                                        int bracketStart = line.lastIndexOf('[');
                                        int bracketEnd = line.lastIndexOf(']');
                                        if (bracketStart != -1 && bracketEnd > bracketStart) {
                                            String users = line.substring(bracketStart + 1, bracketEnd);
                                            for (String u : users.split(",")) {
                                                if (u.trim().equals(username)) {
                                                    hasPermission = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            if (deviceFound)
                                break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    outStream.writeObject("NOK");
                    outStream.flush();
                    return;
                }

                if (!deviceFound) {
                    outStream.writeObject("NOD");
                    outStream.flush();
                    return;
                }

                if (!hasPermission) {
                    outStream.writeObject("NOPERM");
                    outStream.flush();
                    return;
                }

                String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
                String logFilePath = "data/logs/" + houseName + "/" + section + "/" + deviceId + ".csv";
                File logFile = new File(logFilePath);

                Lock logReadLock = getLock(logFilePath).readLock();
                logReadLock.lock();
                try {
                    if (!logFile.exists() || logFile.length() == 0) {
                        outStream.writeObject("NODATA");
                        outStream.flush();
                        return;
                    }

                    // verificar antes de ler o log
                    if (!verifyFileHash(logFilePath)) {
                        System.out.println("NOK-INTEGRITY");
                        System.exit(1);
                    }

                    byte[] data;
                    try {
                        data = lerFicheiroCifrado(logFilePath);
                    } catch (Exception e) {
                        System.err.println("Erro a ler log cifrado: " + e.getMessage());
                        outStream.writeObject("NOK");
                        outStream.flush();
                        return;
                    }

                    // E2E: Obter as chaves das secções às quais o utilizador tem acesso
                    java.util.HashMap<String, byte[]> keysMap = new java.util.HashMap<>();
                    File kf = new File("data/keys/key." + houseName + "." + section + "." + username);
                    if (kf.exists()) keysMap.put(section, java.nio.file.Files.readAllBytes(kf.toPath()));

                    outStream.writeObject(new Object[]{"OK", keysMap});
                    outStream.writeObject((long) data.length);
                    outStream.write(data);
                    outStream.flush();

                    System.out.println("RH sent to " + username + " for " + deviceId + ": " + data.length + " bytes");
                } finally {
                    logReadLock.unlock();
                }
            } finally {
                houseReadLock.unlock();
            }
        }

        private String executeCommand(String houseName, String deviceId, String valueStr, String requestingUser) {
            String houseFilePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(houseFilePath);

            Lock houseWriteLock = getLock(houseFilePath).writeLock();
            houseWriteLock.lock();
            try {
                if (!houseFile.exists()) {
                    return "NOHM";
                }
                // verificar antes de ler
                if (!verifyFileHash(houseFilePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                // Validação do Cliente (E2E): O valor não é validado pelo servidor. Vem Cifrado (Base64).
                // Mas, por segurança, rejeitamos nulos ou vazios
                if (valueStr == null || valueStr.trim().isEmpty()) {
                    return "NOK";
                }

                List<String> lines = new ArrayList<>();
                boolean deviceFound = false;
                boolean hasPermission = false;
                boolean updated = false;

                try {
                    byte[] decBytes = lerFicheiroCifrado(houseFilePath);
                    try (Scanner sc = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        String owner = sc.hasNextLine() ? sc.nextLine().trim() : "";
                        lines.add(owner);

                        if (owner.equals(requestingUser)) {
                            hasPermission = true;
                        }

                        while (sc.hasNextLine()) {
                            String line = sc.nextLine();
                            // Check if this line contains the device
                            // Line format: Section:(d1-s1,d2-s2)[u1,u2]
                            if (line.contains(":" + deviceId + "-") || line.contains("," + deviceId + "-")
                                    || line.contains("(" + deviceId + "-")) {
                                // Start parsing to be precise
                                int startP = line.indexOf('(');
                                int endP = line.lastIndexOf(')');
                                if (startP != -1 && endP > startP) {
                                    String content = line.substring(startP + 1, endP);
                                    String[] devices = content.split(",");
                                    StringBuilder newContent = new StringBuilder();
                                    boolean foundInLine = false;

                                    for (int i = 0; i < devices.length; i++) {
                                        String dev = devices[i].trim();
                                        if (dev.startsWith(deviceId + "-")) {
                                            foundInLine = true;
                                            deviceFound = true;

                                            // Check permission if not owner
                                            if (!hasPermission) {
                                                String suffix = line.substring(endP + 1).trim();
                                                if (suffix.startsWith("[") && suffix.endsWith("]")) {
                                                    String users = suffix.substring(1, suffix.length() - 1);
                                                    for (String u : users.split(",")) {
                                                        if (u.trim().equals(requestingUser)) {
                                                            hasPermission = true;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }

                                            if (hasPermission) {
                                                // Update value
                                                newContent.append(deviceId).append("-").append(valueStr);
                                                updated = true;
                                            } else {
                                                // Keep old value
                                                newContent.append(dev);
                                            }
                                        } else {
                                            newContent.append(dev);
                                        }
                                        if (i < devices.length - 1) {
                                            newContent.append(",");
                                        }
                                    }

                                    if (foundInLine) {
                                        String prefix = line.substring(0, startP + 1);
                                        String suffix = line.substring(endP);
                                        line = prefix + newContent.toString() + suffix;
                                    }
                                }
                            }
                            lines.add(line);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return "Error securely reading house file.";
                }

                if (!deviceFound) {
                    return "NOD";
                }

                if (!hasPermission) {
                    return "NOPERM";
                }

                if (updated) {
                    try {
                        StringBuilder sb = new StringBuilder();
                        for (String l : lines) {
                            sb.append(l).append("\n");
                        }
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes("UTF-8"));
                    } catch (Exception e) {
                        e.printStackTrace();
                        return "Error securely writing to house file.";
                    }
                    // guardar hash da casa depois de escrever
                    try {
                        saveFileHash(houseFilePath);
                    } catch (Exception e) {
                        System.err.println("Erro a guardar hash: " + e.getMessage());
                    }

                    // Escrever no log CSV do dispositivo
                    String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
                    File logDir = new File("data/logs/" + houseName + "/" + section);
                    logDir.mkdirs(); // cria as pastas se não existirem

                    String logFilePath = logDir.getPath() + "/" + deviceId + ".csv";
                    File logFile = new File(logFilePath);

                    Lock logWriteLock = getLock(logFilePath).writeLock();
                    logWriteLock.lock();
                    try {
                        boolean isNewFile = !logFile.exists();
                        StringBuilder logContent = new StringBuilder();

                        if (!isNewFile) {
                            // verify integrity first
                            if (!verifyFileHash(logFilePath)) {
                                System.out.println("NOK-INTEGRITY-LOG");
                                System.exit(1);
                            }
                            try {
                                byte[] existingBytes = lerFicheiroCifrado(logFilePath);
                                logContent.append(new String(existingBytes, "UTF-8"));
                            } catch (Exception e) {
                                System.err.println("Erro a ler log cifrado antigo: " + e.getMessage());
                            }
                        } else {
                            logContent.append("device,value,timestamp\n");
                        }

                        // Appending the new log line
                        logContent.append(deviceId).append(",")
                                .append(valueStr).append(",")
                                .append(java.time.LocalDateTime.now()
                                        .format(java.time.format.DateTimeFormatter
                                                .ofPattern("yyyy-MM-dd HH:mm:ss")))
                                .append("\n");

                        try {
                            escreverFicheiroCifrado(logFilePath, logContent.toString().getBytes("UTF-8"));
                        } catch (Exception e) {
                            System.err.println("Erro a escrever log cifrado: " + e.getMessage());
                        }

                        try {
                            saveFileHash(logFilePath);
                        } catch (Exception e) {
                            System.err.println("Erro a guardar hash do log: " + e.getMessage());
                        }
                    } finally {
                        logWriteLock.unlock();
                    }

                    return "OK";
                }

                return "OK";
            } finally {
                houseWriteLock.unlock();
            }
        }

        private String registerDevice(String houseName, String section, String requestingUser) {
            String houseFilePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(houseFilePath);

            Lock writeLock = getLock(houseFilePath).writeLock();
            writeLock.lock();

            try {
                if (!houseFile.exists()) {
                    return "NOHM";
                }
                // verificar antes de ler
                if (!verifyFileHash(houseFilePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                List<String> lines = new ArrayList<>();
                boolean updated = false;
                String newDeviceId = null;

                try {
                    byte[] decBytes = lerFicheiroCifrado(houseFilePath);
                    try (Scanner sc = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        // Check owner first line
                        String ownerLine = sc.hasNextLine() ? sc.nextLine().trim() : "";
                        lines.add(ownerLine);

                        if (!ownerLine.equals(requestingUser)) {
                            return "NOPERM";
                        }

                        while (sc.hasNextLine()) {
                            String line = sc.nextLine();
                            if (line.startsWith(section + ":")) {
                                int contentStart = line.indexOf('(') + 1;
                                int contentEnd = line.lastIndexOf(')');

                                if (contentStart > 0 && contentEnd >= contentStart) {
                                    String content = line.substring(contentStart, contentEnd).trim();
                                    String suffix = line.substring(contentEnd + 1).trim(); // Keep permissions part
                                    if (suffix.isEmpty())
                                        suffix = "[]";

                                    int nextId = 1;

                                    if (!content.isEmpty()) {
                                        String[] devices = content.split(",");
                                        int maxId = 0;
                                        for (String dev : devices) {
                                            // Format: E1-0 (no permissions inside now)
                                            String idPart = dev.split("-")[0].trim();
                                            if (idPart.startsWith(section)) {
                                                try {
                                                    int num = Integer.parseInt(idPart.substring(section.length()));
                                                    if (num > maxId)
                                                        maxId = num;
                                                } catch (NumberFormatException e) {
                                                    // ignore malformed ID
                                                }
                                            }
                                        }
                                        nextId = maxId + 1;
                                    }

                                    newDeviceId = section + nextId;
                                    String newEntry = newDeviceId + "-0";

                                    if (content.isEmpty()) {
                                        content = newEntry;
                                    } else {
                                        content += "," + newEntry;
                                    }
                                    line = section + ":(" + content + ")" + suffix;
                                    updated = true;
                                }
                            }
                            lines.add(line);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return "Error reading securely from house file.";
                }

                if (updated) {
                    try {
                        StringBuilder sb = new StringBuilder();
                        for (String l : lines) {
                            sb.append(l).append("\n");
                        }
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes("UTF-8"));
                    } catch (Exception e) {
                        e.printStackTrace();
                        return "Error securely writing to house file.";
                    }
                    // guardar hash apos escrever
                    try {
                        saveFileHash(houseFilePath);
                    } catch (Exception e) {
                        System.err.println("Erro a guardar hash: " + e.getMessage());
                    }
                    System.out.println("Registered device " + newDeviceId + " in " + houseName);
                    return "OK";
                } else {
                    return "Section " + section + " not found or error reading file.";
                }
            } finally {
                writeLock.unlock();
            }
        }

        private String addPermission(String targetUser, String houseName, String section, String requestingUser) {
            String houseFilePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(houseFilePath);

            Lock writeLock = getLock(houseFilePath).writeLock();
            writeLock.lock();

            try {
                if (!houseFile.exists()) {
                    return "NOHM";
                }

                if (!verifyFileHash(houseFilePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                if (!userExists(targetUser)) {
                    return "NOUSER";
                }

                List<String> lines = new ArrayList<>();
                boolean updated = false;

                try {
                    byte[] decBytes = lerFicheiroCifrado(houseFilePath);
                    try (Scanner sc = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        // Check owner first line - SAFE READ
                        String ownerLine = "";
                        if (sc.hasNextLine()) {
                            ownerLine = sc.nextLine().trim();
                        }
                        lines.add(ownerLine);

                        if (!ownerLine.equals(requestingUser)) {
                            return "NOPERM";
                        }

                        while (sc.hasNextLine()) {
                            String line = sc.nextLine();
                            // Check format validity
                            if (!line.contains(":")) {
                                lines.add(line);
                                continue;
                            }

                            String currentSection = line.substring(0, line.indexOf(':'));
                            boolean isTargetSection = section.equalsIgnoreCase("all") || currentSection.equals(section);

                            if (isTargetSection) {
                                int contentEnd = line.lastIndexOf(')');

                                if (contentEnd != -1) {
                                    String prefix = line.substring(0, contentEnd + 1); // "Section:(...)"
                                    String suffix = line.substring(contentEnd + 1).trim();
                                    if (suffix.isEmpty())
                                        suffix = "[]";

                                    String currentUsers = "";
                                    if (suffix.startsWith("[") && suffix.endsWith("]")) {
                                        currentUsers = suffix.substring(1, suffix.length() - 1);
                                    }

                                    boolean alreadyHas = false;
                                    if (!currentUsers.isEmpty()) {
                                        for (String u : currentUsers.split(",")) {
                                            if (u.trim().equals(targetUser)) {
                                                alreadyHas = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (!alreadyHas) {
                                        if (currentUsers.isEmpty()) {
                                            suffix = "[" + targetUser + "]";
                                        } else {
                                            suffix = "[" + currentUsers + "," + targetUser + "]";
                                        }
                                        line = prefix + suffix;
                                        updated = true;
                                    }
                                }
                            }
                            lines.add(line);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return "Error securely reading house file.";
                }

                if (updated) {
                    try {
                        StringBuilder sb = new StringBuilder();
                        for (String l : lines) {
                            sb.append(l).append("\n");
                        }
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes("UTF-8"));
                        
                        try {
                            saveFileHash(houseFilePath);
                        } catch (Exception e) {
                            System.err.println("Erro a guardar hash: " + e.getMessage());
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        return "Error writing to house file.";
                    }
                    return "OK";
                } else {
                    if (section.equalsIgnoreCase("all")) {
                        return "OK";
                    }
                    return "Section " + section + " not found.";
                }
            } finally {
                writeLock.unlock();
            }
        }

        private String createHouse(String houseName, String owner, java.util.HashMap<String, byte[]> sectionKeys) {
            File homesDir = new File("data/homes");
            if (!homesDir.exists()) {
                homesDir.mkdirs();
            }

            // Criar pasta de chaves se não existir
            File keysDir = new File("data/keys");
            if (!keysDir.exists()) {
                keysDir.mkdirs();
            }

            String houseFilePath = "data/homes/" + houseName + ".txt";
            File houseFile = new File(houseFilePath);

            Lock writeLock = getLock(houseFilePath).writeLock();
            writeLock.lock();

            try {
                if (houseFile.exists()) {
                    return "NOK";
                }

                try {
                    // 1. Guardar a casa
                    StringBuilder sb = new StringBuilder();
                    sb.append(owner).append("\n");
                    sb.append("E:()[]\n");
                    sb.append("G:()[]\n");
                    sb.append("L:()[]\n");
                    sb.append("M:()[]\n");
                    sb.append("P:()[]\n");
                    sb.append("S:()[]\n");
                    escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes("UTF-8"));
                    System.out.println("House " + houseName + " created securely for owner " + owner);
                    
                    // 2. Guardar as chaves embrulhadas no formato key.<hm>.<s>.<owner>
                    if (sectionKeys != null && !sectionKeys.isEmpty()) {
                        for (java.util.Map.Entry<String, byte[]> entry : sectionKeys.entrySet()) {
                            String s = entry.getKey();
                            byte[] keyBytes = entry.getValue();
                            String keyPath = "data/keys/key." + houseName + "." + s + "." + owner;
                            java.nio.file.Files.write(java.nio.file.Paths.get(keyPath), keyBytes);
                        }
                        System.out.println("Section keys para casa " + houseName + " criadas com sucesso (owner: " + owner + ").");
                    }
                } catch (Exception e) {
                    System.err.println("Error creating house file: " + e.getMessage());
                    return "NOK";
                }

                // guardar hash apos criar o ficheiro
                try {
                    saveFileHash(houseFilePath);
                } catch (Exception e) {
                    System.err.println("Erro a guardar hash: " + e.getMessage());
                }

                return "OK";
            } finally {
                writeLock.unlock();
            }
        }

        private boolean userExists(String username) {
            synchronized (SpertaServer.class) {
                File userFile = new File("data/users.txt");
                if (!userFile.exists())
                    return false;
                try {
                    byte[] decBytes = lerFicheiroCifrado("data/users.txt");
                    if (decBytes != null && decBytes.length > 0) {
                        try (Scanner scanner = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                            while (scanner.hasNextLine()) {
                                String line = scanner.nextLine();
                                String[] parts = line.split(":");
                                if (parts.length >= 1 && parts[0].equals(username)) {
                                    return true;
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Erro ao ler users.txt cifrado no userExists: " + e.getMessage());
                }
                return false;
            }
        }

        private int authenticateUser(String username, String password,
                ObjectInputStream in, ObjectOutputStream out)
                throws Exception {
            synchronized (SpertaServer.class) {
                File userFile = new File("data/users.txt");
                if (!userFile.getParentFile().exists())
                    userFile.getParentFile().mkdirs();
                if (!userFile.exists()) {
                    // Apenas criar se não existe
                    // Só gravamos "vazio" cifrado para depois lhe darmos write append limpo
                    escreverFicheiroCifrado("data/users.txt", new byte[0]);
                }
                
                // verificar antes de ler
                if (!verifyFileHash("data/users.txt")) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                List<String> allLines = new ArrayList<>();
                boolean foundUser = false;
                boolean passwordMatch = false;

                byte[] decBytes = lerFicheiroCifrado("data/users.txt");
                if (decBytes != null && decBytes.length > 0) {
                    try (Scanner scanner = new Scanner(new java.io.ByteArrayInputStream(decBytes))) {
                        while (scanner.hasNextLine()) {
                            String line = scanner.nextLine().trim();
                            if (line.isEmpty())
                                continue;
                            allLines.add(line);
                            String[] parts = line.split(":");
                            if (parts.length >= 1 && parts[0].equals(username)) {
                                foundUser = true;
                                if (parts.length == 3) {
                                    //Autenticaçao de clientes
                                    // Formato correto: userid:hash:salt
                                    String storedHash = parts[1];
                                    String storedSalt = parts[2];
                                    String computedHash = hashPassword(password, storedSalt);
                                    passwordMatch = storedHash.equals(computedHash);
                                }
                            }
                        }
                    }
                }

                if (foundUser) {
                    return passwordMatch ? 1 : 0;

                } else {
                    // Servidore protege a confidencialidade das passwords dos utilizadores.
                    // Novo utilizador — gerar hash+salt e pedir certificado
                    String salt = generateSalt();
                    String hash = hashPassword(password, salt);

                    String newUserLine = username + ":" + hash + ":" + salt + System.lineSeparator();
                    if (decBytes == null) decBytes = new byte[0];
                    byte[] newBytes = newUserLine.getBytes("UTF-8");
                    byte[] finalData = new byte[decBytes.length + newBytes.length];
                    System.arraycopy(decBytes, 0, finalData, 0, decBytes.length);
                    System.arraycopy(newBytes, 0, finalData, decBytes.length, newBytes.length);

                    // Escrever ficheiro cifrado em vez do antigo FileOutputStream 
                    escreverFicheiroCifrado("data/users.txt", finalData);
                    System.out.println("New user registered: " + username);
                    
                    // guardar hash após escrever (O SHA256 é feito no ficheiro CIFRADO)
                    saveFileHash("data/users.txt");
                    
                    // Pedir certificado ao cliente
                    out.writeObject("SEND-CERT");
                    out.flush();

                    // Receber o certificado (array de bytes)
                    byte[] certBytes = (byte[]) in.readObject();

                    // Guardar o certificado
                    File certDir = new File("data/certs");
                    certDir.mkdirs();
                    File certFile = new File(certDir, username + ".cert");
                    try (FileOutputStream fos = new FileOutputStream(certFile)) {
                        fos.write(certBytes);
                    }
                    System.out.println("Certificate received and saved for: " + username);

                    return 2;
                }
            }
        }

        private String generateSalt() {
            byte[] salt = new byte[16];
            new java.security.SecureRandom().nextBytes(salt);
            return java.util.Base64.getEncoder().encodeToString(salt);
        }

        private String hashPassword(String password, String salt) throws Exception {
            // Concatenar password com salt
            String combined = password + salt;

            // Calcular SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes("UTF-8"));

            // Converter para Base64 para guardar no ficheiro
            return java.util.Base64.getEncoder().encodeToString(hash);
        }

        //Servidor verifica a integridade
        private void saveFileHash(String filePath) throws Exception {
            byte[] content = Files.readAllBytes(Paths.get(filePath));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            String hashBase64 = java.util.Base64.getEncoder().encodeToString(hash);

            // Guarda o hash num ficheiro com o mesmo nome + ".hash"
            try (java.io.PrintWriter pw = new java.io.PrintWriter(filePath + ".hash")) {
                pw.print(hashBase64);
            }
        }

        private boolean verifyFileHash(String filePath) {
            File hashFile = new File(filePath + ".hash");
            if (!hashFile.exists())
                return true;
            try {
                String storedHash = new String(Files.readAllBytes(hashFile.toPath())).trim();
                byte[] content = Files.readAllBytes(Paths.get(filePath));
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(content);
                String currentHash = java.util.Base64.getEncoder().encodeToString(hash);
                return storedHash.equals(currentHash);
            } catch (Exception e) {
                //mensagem de erro da integridade
                System.err.println("Erro a verificar integridade: " + e.getMessage());
                return false;
            }
        }
    }
}