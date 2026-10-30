package server;

import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import utils.CryptoService;

public class SpertaServer {
    
    // Concurrency control: per-file read/write reentrant locks
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
            pbeSalt = CryptoService.generateRandomSalt();
            Files.write(saltFile.toPath(), pbeSalt);
        }
    }

    public static byte[] lerFicheiroCifrado(String caminho) throws Exception {
        File f = new File(caminho);
        if (!f.exists() || f.length() == 0) return null;
        
        byte[] fileData = Files.readAllBytes(Paths.get(caminho));
        if (fileData.length < 16) return null;
        return CryptoService.decryptPBE(fileData, cipherPassword, pbeSalt);
    }

    public static void escreverFicheiroCifrado(String caminho, byte[] textoLimpo) throws Exception {
        byte[] finalFileData = CryptoService.encryptPBE(textoLimpo, cipherPassword, pbeSalt);
        
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

        String cipherPasswordArg = args[1];
        String keystorePath = args[2];
        String keystorePassword = args[3];

        try {
            initPBE(cipherPasswordArg);
        } catch (Exception e) {
            System.err.println("Failed to initialize PBE engine: " + e.getMessage());
            System.exit(1);
        }

        // Configure system properties for SSL/TLS handshake
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);

        String referenceClientPath = loadExpectedClientPath();
        if (referenceClientPath == null) {
            System.out.println("WARNING: attestation.txt not found. Client attestation disabled.");
        } else {
            System.out.println("Attestation active with reference binary: " + referenceClientPath);
        }

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
                if (line.startsWith("SpertaClient:")) {
                    return line.substring("SpertaClient:".length()).trim();
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading attestation.txt: " + e.getMessage());
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

        @Override
        @SuppressWarnings("unchecked")
        public void run() {
            ObjectInputStream inStream = null;
            ObjectOutputStream outStream = null;

            try {
                outStream = new ObjectOutputStream(socket.getOutputStream());
                inStream = new ObjectInputStream(socket.getInputStream());

                // STEP 1: Binary Attestation
                if (referenceClientPath != null && !handleAttestation(inStream, outStream)) {
                    socket.close();
                    return;
                }

                // STEP 2: Authentication Loop with Retry
                String username = null;
                while (true) {
                    String user = (String) inStream.readObject();
                    String pass = (String) inStream.readObject();
                    System.out.println("Received credentials from: " + user);

                    int authResult = authenticateUser(user, pass, inStream, outStream);

                    if (authResult == 0) {
                        // WRONG-PWD
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
                        // OK-NEW-USER (certificate handled within authenticateUser)
                        System.out.println("OK-NEW-USER: " + user);
                        username = user;
                        break;
                    }
                }

                // STEP 3: Message / Command Processing Loop
                receiveMessages(inStream, outStream, username);

            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Connection closed for client: " + (username != null ? username : "unauthenticated"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private boolean handleAttestation(ObjectInputStream in, ObjectOutputStream out)
                throws IOException {

            // 1. Generate and send 8-byte challenge nonce
            SecureRandom random = new SecureRandom();
            long nonce = random.nextLong();
            out.writeLong(nonce);
            out.flush();

            try {
                // 2. Receive client calculated hash
                byte[] clientHash = (byte[]) in.readObject();

                // 3. Read reference binary
                File referenceFile = new File(referenceClientPath);
                if (!referenceFile.exists()) {
                    System.err.println("Reference executable not found: " + referenceClientPath);
                    out.writeObject("NOK-ATTEST");
                    out.flush();
                    return false;
                }
                byte[] referenceJarBytes = Files.readAllBytes(referenceFile.toPath());

                // 4. Compute server hash using CryptoService
                byte[] serverHash = CryptoService.computeHashWithNonce(nonce, referenceJarBytes);

                // 5. Compare digests
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
                System.err.println("Attestation error: " + e.getMessage());
                try {
                    out.writeObject("NOK-ATTEST");
                    out.flush();
                } catch (Exception ignored) {
                }
                return false;
            }
        }

        @SuppressWarnings("unchecked")
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
                                System.err.println("Error receiving section keys: " + e.getMessage());
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
                                    // 1. Read target user's certificate
                                    File certFile = new File("data/certs/" + targetUser + ".cert");
                                    byte[] targetCertBytes = null;
                                    if (certFile.exists()) {
                                        targetCertBytes = Files.readAllBytes(certFile.toPath());
                                    }
                                    
                                    // 2. Read caller's wrapped section keys
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
                                    
                                    // 3. Dispatch to client to decrypt and re-wrap for target user
                                    Object[] e2eData = new Object[]{"E2E_ADD", keysToWrap, targetCertBytes};
                                    outStream.writeObject(e2eData);
                                    outStream.flush();
                                    
                                    // 4. Persist re-wrapped keys
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
                                        response = "NOK - Failed to receive re-wrapped keys (E2E).";
                                    }
                                    
                                } catch (Exception e) {
                                    System.err.println("Error during E2E_ADD: " + e.getMessage());
                                    response = "NOK - Internal error in E2E_ADD.";
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
                        // Format: GET_KEY <hm> <sec>
                        if (parts.length >= 3) {
                            String houseName = parts[1];
                            String section = parts[2].toUpperCase();
                            File kf = new File("data/keys/key." + houseName + "." + section + "." + username);
                            if (kf.exists()) {
                                byte[] keyBytes = Files.readAllBytes(kf.toPath());
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
                        if (parts.length >= 2) {
                            handleRT(parts[1], username, outStream);
                        } else {
                            outStream.writeObject("NOK");
                            outStream.flush();
                        }

                    } else if (command.equals("RH")) {
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

                if (!verifyFileHash(housePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

                StringBuilder content = new StringBuilder();
                boolean hasPermission = false;
                List<String> accessibleSections = new ArrayList<>();

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
                                
                            String secName = line.substring(0, line.indexOf(':'));
                            if (!accessibleSections.contains(secName)) {
                                accessibleSections.add(secName);
                            }

                            int parenStart = line.indexOf('(');
                            int parenEnd = line.indexOf(')');
                            if (parenStart == -1 || parenEnd <= parenStart)
                                continue;

                            String devicesStr = line.substring(parenStart + 1, parenEnd).trim();
                            if (devicesStr.isEmpty())
                                continue;

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

                // Return wrapped section keys accessible to user
                java.util.HashMap<String, byte[]> keysMap = new java.util.HashMap<>();
                for (String s : accessibleSections) {
                    File kf = new File("data/keys/key." + houseName + "." + s + "." + username);
                    if (kf.exists()) keysMap.put(s, Files.readAllBytes(kf.toPath()));
                }

                byte[] data = content.toString().getBytes(StandardCharsets.UTF_8);
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
                if (!houseFile.exists()) {
                    outStream.writeObject("NOHM");
                    outStream.flush();
                    return;
                }

                if (!verifyFileHash(housePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

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

                    if (!verifyFileHash(logFilePath)) {
                        System.out.println("NOK-INTEGRITY");
                        System.exit(1);
                    }

                    byte[] data;
                    try {
                        data = lerFicheiroCifrado(logFilePath);
                    } catch (Exception e) {
                        System.err.println("Error reading encrypted log file: " + e.getMessage());
                        outStream.writeObject("NOK");
                        outStream.flush();
                        return;
                    }

                    java.util.HashMap<String, byte[]> keysMap = new java.util.HashMap<>();
                    File kf = new File("data/keys/key." + houseName + "." + section + "." + username);
                    if (kf.exists()) keysMap.put(section, Files.readAllBytes(kf.toPath()));

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
                if (!verifyFileHash(houseFilePath)) {
                    System.out.println("NOK-INTEGRITY");
                    System.exit(1);
                }

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
                            if (line.contains(":" + deviceId + "-") || line.contains("," + deviceId + "-")
                                    || line.contains("(" + deviceId + "-")) {
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
                                                newContent.append(deviceId).append("-").append(valueStr);
                                                updated = true;
                                            } else {
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
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes(StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        e.printStackTrace();
                        return "Error securely writing to house file.";
                    }

                    try {
                        saveFileHash(houseFilePath);
                    } catch (Exception e) {
                        System.err.println("Error saving house hash: " + e.getMessage());
                    }

                    String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
                    File logDir = new File("data/logs/" + houseName + "/" + section);
                    logDir.mkdirs();

                    String logFilePath = logDir.getPath() + "/" + deviceId + ".csv";
                    File logFile = new File(logFilePath);

                    Lock logWriteLock = getLock(logFilePath).writeLock();
                    logWriteLock.lock();
                    try {
                        boolean isNewFile = !logFile.exists();
                        StringBuilder logContent = new StringBuilder();

                        if (!isNewFile) {
                            if (!verifyFileHash(logFilePath)) {
                                System.out.println("NOK-INTEGRITY-LOG");
                                System.exit(1);
                            }
                            try {
                                byte[] existingBytes = lerFicheiroCifrado(logFilePath);
                                logContent.append(new String(existingBytes, StandardCharsets.UTF_8));
                            } catch (Exception e) {
                                System.err.println("Error reading existing encrypted log: " + e.getMessage());
                            }
                        } else {
                            logContent.append("device,value,timestamp\n");
                        }

                        logContent.append(deviceId).append(",")
                                .append(valueStr).append(",")
                                .append(java.time.LocalDateTime.now()
                                        .format(java.time.format.DateTimeFormatter
                                                .ofPattern("yyyy-MM-dd HH:mm:ss")))
                                .append("\n");

                        try {
                            escreverFicheiroCifrado(logFilePath, logContent.toString().getBytes(StandardCharsets.UTF_8));
                        } catch (Exception e) {
                            System.err.println("Error writing encrypted log: " + e.getMessage());
                        }

                        try {
                            saveFileHash(logFilePath);
                        } catch (Exception e) {
                            System.err.println("Error saving log hash: " + e.getMessage());
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
                                    String suffix = line.substring(contentEnd + 1).trim();
                                    if (suffix.isEmpty())
                                        suffix = "[]";

                                    int nextId = 1;

                                    if (!content.isEmpty()) {
                                        String[] devices = content.split(",");
                                        int maxId = 0;
                                        for (String dev : devices) {
                                            String idPart = dev.split("-")[0].trim();
                                            if (idPart.startsWith(section)) {
                                                try {
                                                    int num = Integer.parseInt(idPart.substring(section.length()));
                                                    if (num > maxId)
                                                        maxId = num;
                                                } catch (NumberFormatException ignored) {
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
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes(StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        e.printStackTrace();
                        return "Error securely writing to house file.";
                    }
                    try {
                        saveFileHash(houseFilePath);
                    } catch (Exception e) {
                        System.err.println("Error saving hash: " + e.getMessage());
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
                            if (!line.contains(":")) {
                                lines.add(line);
                                continue;
                            }

                            String currentSection = line.substring(0, line.indexOf(':'));
                            boolean isTargetSection = section.equalsIgnoreCase("all") || currentSection.equals(section);

                            if (isTargetSection) {
                                int contentEnd = line.lastIndexOf(')');

                                if (contentEnd != -1) {
                                    String prefix = line.substring(0, contentEnd + 1);
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
                        escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes(StandardCharsets.UTF_8));
                        
                        try {
                            saveFileHash(houseFilePath);
                        } catch (Exception e) {
                            System.err.println("Error saving hash: " + e.getMessage());
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
                    StringBuilder sb = new StringBuilder();
                    sb.append(owner).append("\n");
                    sb.append("E:()[]\n");
                    sb.append("G:()[]\n");
                    sb.append("L:()[]\n");
                    sb.append("M:()[]\n");
                    sb.append("P:()[]\n");
                    sb.append("S:()[]\n");
                    escreverFicheiroCifrado(houseFilePath, sb.toString().getBytes(StandardCharsets.UTF_8));
                    System.out.println("House " + houseName + " created securely for owner " + owner);
                    
                    if (sectionKeys != null && !sectionKeys.isEmpty()) {
                        for (java.util.Map.Entry<String, byte[]> entry : sectionKeys.entrySet()) {
                            String s = entry.getKey();
                            byte[] keyBytes = entry.getValue();
                            String keyPath = "data/keys/key." + houseName + "." + s + "." + owner;
                            Files.write(Paths.get(keyPath), keyBytes);
                        }
                        System.out.println("Section keys for house " + houseName + " initialized successfully for owner: " + owner);
                    }
                } catch (Exception e) {
                    System.err.println("Error creating house file: " + e.getMessage());
                    return "NOK";
                }

                try {
                    saveFileHash(houseFilePath);
                } catch (Exception e) {
                    System.err.println("Error saving hash: " + e.getMessage());
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
                    System.err.println("Error reading encrypted users.txt in userExists: " + e.getMessage());
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
                    escreverFicheiroCifrado("data/users.txt", new byte[0]);
                }
                
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
                    byte[] saltBytes = CryptoService.generateRandomSalt();
                    String salt = Base64.getEncoder().encodeToString(saltBytes);
                    String hash = hashPassword(password, salt);

                    String newUserLine = username + ":" + hash + ":" + salt + System.lineSeparator();
                    if (decBytes == null) decBytes = new byte[0];
                    byte[] newBytes = newUserLine.getBytes(StandardCharsets.UTF_8);
                    byte[] finalData = new byte[decBytes.length + newBytes.length];
                    System.arraycopy(decBytes, 0, finalData, 0, decBytes.length);
                    System.arraycopy(newBytes, 0, finalData, decBytes.length, newBytes.length);

                    escreverFicheiroCifrado("data/users.txt", finalData);
                    System.out.println("New user registered: " + username);
                    
                    saveFileHash("data/users.txt");
                    
                    out.writeObject("SEND-CERT");
                    out.flush();

                    byte[] certBytes = (byte[]) in.readObject();

                    File certDir = new File("data/certs");
                    certDir.mkdirs();
                    File certFile = new File(certDir, username + ".cert");
                    try (FileOutputStream fos = new FileOutputStream(certFile)) {
                        fos.write(certBytes);
                    }
                    System.out.println("Certificate received and stored for: " + username);

                    return 2;
                }
            }
        }

        private String hashPassword(String password, String salt) throws Exception {
            String combined = password + salt;
            byte[] hashBytes = CryptoService.computeSHA256(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        }

        private void saveFileHash(String filePath) throws Exception {
            byte[] content = Files.readAllBytes(Paths.get(filePath));
            byte[] hash = CryptoService.computeSHA256(content);
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

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
                byte[] hash = CryptoService.computeSHA256(content);
                String currentHash = Base64.getEncoder().encodeToString(hash);
                return storedHash.equals(currentHash);
            } catch (Exception e) {
                System.err.println("Integrity verification error: " + e.getMessage());
                return false;
            }
        }
    }
}