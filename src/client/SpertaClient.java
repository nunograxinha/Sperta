package client;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import utils.CryptoService;

public class SpertaClient {

    public static void main(String[] args) {
        System.out.println("SpertaClient: main");
        SpertaClient client = new SpertaClient();
        client.startClient(args);
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

        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);

        String serverAddress = serverAddressRaw;
        int port = 22345;

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

                // STEP 1: Binary Attestation
                if (!doAttestation(outStream, inStream)) {
                    return;
                }

                // STEP 2: Authentication
                if (!doAuth(outStream, inStream, username, password, scanner, keystorePath, keystorePassword)) {
                    return;
                }

                // STEP 3: Command Interaction Loop
                interactWithServer(outStream, inStream, scanner, username, keystorePath, keystorePassword);

            } finally {
                socket.close();
            }

        } catch (UnknownHostException e) {
            System.err.println("Server not found: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("I/O Error: " + e.getMessage());
        } catch (ClassNotFoundException e) {
            System.err.println("Class not found: " + e.getMessage());
        }
    }

    private boolean doAttestation(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {

        long nonce = in.readLong();
        System.out.println("Received attestation challenge nonce: " + nonce);

        byte[] calculatedHash;
        try {
            calculatedHash = calculateJarHashWithNonce(nonce);
        } catch (Exception e) {
            System.err.println("Error computing attestation hash: " + e.getMessage());
            calculatedHash = new byte[0];
        }

        out.writeObject(calculatedHash);
        out.flush();

        String response = (String) in.readObject();
        if ("OK-ATTEST".equals(response)) {
            System.out.println("Attestation OK");
            return true;
        } else {
            System.out.println("Attestation FAILED: " + response);
            return false;
        }
    }

    private byte[] calculateJarHashWithNonce(long nonce) throws Exception {
        String jarPath = SpertaClient.class
            .getProtectionDomain()
            .getCodeSource()
            .getLocation()
            .toURI()
            .getPath();

        File jarFile = new File(jarPath);
        if (jarFile.isDirectory()) {
             jarFile = new File("SpertaClient.jar");
             if (!jarFile.exists()) {
                 throw new Exception("Reference client binary not found at: " + jarFile.getAbsolutePath());
             }
        }

        if (!jarFile.exists() || !jarFile.isFile()) {
            throw new Exception("JAR file not found at " + jarFile.getAbsolutePath());
        }

        byte[] jarBytes = Files.readAllBytes(jarFile.toPath());
        return CryptoService.computeHashWithNonce(nonce, jarBytes);
    }

    private boolean doAuth(ObjectOutputStream out, ObjectInputStream in,
            String username, String password, Scanner scanner,
            String keystorePath, String keystorePassword)
            throws IOException, ClassNotFoundException {

        while (true) {
            out.writeObject(username);
            out.writeObject(password);
            out.flush();

            Object response = in.readObject();

            if (response instanceof String) {
                if ("SEND-CERT".equals(response)) {
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
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
                ks.load(fis, keystorePassword.toCharArray());
            }

            Certificate cert = ks.getCertificate(username);
            if (cert == null) {
                java.util.Enumeration<String> aliases = ks.aliases();
                if (aliases.hasMoreElements()) {
                    cert = ks.getCertificate(aliases.nextElement());
                }
            }

            if (cert == null) {
                System.err.println("Certificate not found in keystore.");
                out.writeObject(new byte[0]);
            } else {
                out.writeObject(cert.getEncoded());
                System.out.println("Certificate dispatched to server.");
            }
            out.flush();

        } catch (Exception e) {
            System.err.println("Error sending certificate: " + e.getMessage());
            try {
                out.writeObject(new byte[0]);
                out.flush();
            } catch (Exception ignored) {
            }
        }
    }

    @SuppressWarnings("unchecked")
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

                // E2E EC: Encrypt device value
                if (command.equals("EC") && parts.length == 4) {
                    String hm = parts[1];
                    String d = parts[2];
                    String section = String.valueOf(d.charAt(0)).toUpperCase();
                    try {
                        int v = Integer.parseInt(parts[3]);
                        if (v < 0 || v > 600) {
                            System.out.println("Error: Value must be an integer between 0 and 600.");
                            continue;
                        }

                        outStream.writeObject("GET_KEY " + hm + " " + section);
                        outStream.flush();

                        Object keyResp = inStream.readObject();
                        if (keyResp instanceof byte[]) {
                            PrivateKey privKey = CryptoService.loadPrivateKey(keystorePath, keystorePassword.toCharArray(), username);
                            SecretKey aesKey = CryptoService.unwrapKeyRSA((byte[]) keyResp, privKey);

                            byte[] encVal = CryptoService.encryptAES(String.valueOf(v), aesKey);
                            String newValBase64 = Base64.getEncoder().encodeToString(encVal);

                            line = "EC " + hm + " " + d + " " + newValBase64;
                            parts = line.split(" ");
                        } else {
                            System.out.println("E2E Error: Failed to obtain section key. Server: " + keyResp);
                            continue;
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("Error: EC command requires an integer value.");
                        continue;
                    } catch (Exception e) {
                        System.out.println("E2E Error: " + e.getMessage());
                        continue;
                    }
                }

                outStream.writeObject(line);

                if (command.equals("CREATE") && parts.length >= 2) {
                    try {
                        HashMap<String, byte[]> wrappedKeys = generateAndWrapSectionKeys(username, keystorePath, keystorePassword);
                        outStream.writeObject(wrappedKeys);
                    } catch (Exception e) {
                        System.err.println("Error generating section keys: " + e.getMessage());
                        outStream.writeObject(new HashMap<String, byte[]>());
                    }
                }

                outStream.flush();

                if (command.equals("RT")) {
                    receiveFile(inStream, buildRTFilename(parts), username, keystorePath, keystorePassword);
                } else if (command.equals("RH")) {
                    receiveFile(inStream, buildRHFilename(parts), username, keystorePath, keystorePassword);
                } else if (command.equals("ADD") && parts.length >= 4) {
                    Object resp = inStream.readObject();
                    if (resp instanceof Object[]) {
                        Object[] e2eData = (Object[]) resp;
                        if ("E2E_ADD".equals(e2eData[0])) {
                            HashMap<String, byte[]> keysToWrap = (HashMap<String, byte[]>) e2eData[1];
                            byte[] targetCertBytes = (byte[]) e2eData[2];

                            try {
                                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                                Certificate targetCert = certFactory.generateCertificate(new java.io.ByteArrayInputStream(targetCertBytes));

                                String currentTrustStorePath = System.getProperty("javax.net.ssl.trustStore");
                                String currentTrustStorePass = System.getProperty("javax.net.ssl.trustStorePassword");

                                KeyStore ts = KeyStore.getInstance("PKCS12");
                                try (java.io.FileInputStream fis = new java.io.FileInputStream(currentTrustStorePath)) {
                                    ts.load(fis, currentTrustStorePass.toCharArray());
                                }

                                String targetUser = parts[1];
                                ts.setCertificateEntry(targetUser, targetCert);

                                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(currentTrustStorePath)) {
                                    ts.store(fos, currentTrustStorePass.toCharArray());
                                }
                                System.out.println("[TRUST] Certificate for " + targetUser + " saved to truststore.");

                            } catch (Exception e) {
                                System.err.println("[TRUST] Error storing certificate into truststore: " + e.getMessage());
                            }

                            try {
                                HashMap<String, byte[]> newWrappedKeys = rewrapSectionKeys(keysToWrap, targetCertBytes, username, keystorePath, keystorePassword);
                                outStream.writeObject(newWrappedKeys);
                                outStream.flush();

                                String finalResp = (String) inStream.readObject();
                                System.out.println("[SERVER]: " + finalResp);
                            } catch (Exception e) {
                                System.err.println("Failed to re-wrap keys: " + e.getMessage());
                                outStream.writeObject(new HashMap<String, byte[]>());
                            }
                        }
                    } else if (resp instanceof String) {
                        System.out.println("[SERVER]: " + resp);
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

    private HashMap<String, byte[]> generateAndWrapSectionKeys(String username, String ksPath, String ksPass) throws Exception {
        HashMap<String, byte[]> map = new HashMap<>();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(ksPath)) {
            ks.load(fis, ksPass.toCharArray());
        }

        Certificate cert = ks.getCertificate(username);
        if (cert == null) {
            java.util.Enumeration<String> aliases = ks.aliases();
            if (aliases.hasMoreElements()) {
                cert = ks.getCertificate(aliases.nextElement());
            }
        }
        if (cert == null) {
            throw new Exception("Certificate not found in keystore.");
        }

        PublicKey pubKey = CryptoService.getPublicKeyFromCertBytes(cert.getEncoded());

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

        PrivateKey privKey = CryptoService.loadPrivateKey(ksPath, ksPass.toCharArray(), username);
        PublicKey targetPubKey = CryptoService.getPublicKeyFromCertBytes(targetCertBytes);

        for (Map.Entry<String, byte[]> entry : keysToWrap.entrySet()) {
            SecretKey rawKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
            byte[] newWrappedBytes = CryptoService.wrapKeyRSA(rawKey, targetPubKey);
            newWrappedKeys.put(entry.getKey(), newWrappedBytes);
        }

        return newWrappedKeys;
    }

    @SuppressWarnings("unchecked")
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

        long fileSize = (Long) in.readObject();
        byte[] data = new byte[(int) fileSize];

        int totalRead = 0;
        while (totalRead < fileSize) {
            int read = in.read(data, totalRead, (int) (fileSize - totalRead));
            if (read == -1)
                break;
            totalRead += read;
        }

        String contentStr = new String(data, StandardCharsets.UTF_8);

        PrivateKey privKey = CryptoService.loadPrivateKey(ksPath, ksPass.toCharArray(), username);

        HashMap<String, SecretKey> aesKeys = new HashMap<>();
        if (wrappedKeysMap != null) {
            for (Map.Entry<String, byte[]> entry : wrappedKeysMap.entrySet()) {
                try {
                    SecretKey aesKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
                    aesKeys.put(entry.getKey(), aesKey);
                } catch (Exception e) {
                    System.err.println("Failed to unwrap section key " + entry.getKey() + ": " + e.getMessage());
                }
            }
        }

        StringBuilder decryptedContent = new StringBuilder();
        Scanner sc = new Scanner(contentStr);

        while (sc.hasNextLine()) {
            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;

            if (line.contains(",")) {
                String[] parts = line.split(",");
                if (parts.length >= 3 && !line.startsWith("device,value")) {
                    String devId = parts[0];
                    String encryptedVal = parts[1].trim();
                    String sec = String.valueOf(devId.charAt(0)).toUpperCase();
                    SecretKey k = aesKeys.get(sec);

                    if (k != null && isBase64(encryptedVal)) {
                        try {
                            byte[] dec = Base64.getDecoder().decode(encryptedVal);
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
                            byte[] dec = Base64.getDecoder().decode(encryptedVal);
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

        byte[] finalDecBytes = decryptedContent.toString().getBytes(StandardCharsets.UTF_8);
        Files.write(Paths.get(localFilename), finalDecBytes);

        System.out.println("File saved: " + localFilename);
        System.out.println("--- Content ---");
        System.out.println(decryptedContent);
        System.out.println("---------------");
    }

    private boolean isBase64(String s) {
        try {
            Base64.getDecoder().decode(s);
            return true;
        } catch (Exception e) {
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