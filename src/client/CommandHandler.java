package client;

import utils.CryptoService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKey;

/**
 * Handles the interactive terminal session, command parsing, E2E encryption dispatch,
 * and decryption of received server files (RT/RH).
 */
@SuppressWarnings("java:S106")
public class CommandHandler {

    private final ObjectOutputStream outStream;
    private final ObjectInputStream inStream;
    private final Scanner scanner;
    private final String username;
    private final String keystorePath;
    private final String keystorePassword;
    private static final String SERVER_PREFIX = "[SERVER]: ";

    public CommandHandler(ObjectOutputStream outStream, ObjectInputStream inStream, Scanner scanner,
                          String username, String keystorePath, String keystorePassword) {
        this.outStream = outStream;
        this.inStream = inStream;
        this.scanner = scanner;
        this.username = username;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
    }

    public void startLoop() {
        printBanner();
        while (scanner.hasNextLine()) {
            System.out.print("> ");
            String line = scanner.nextLine().trim();
            if (!line.isEmpty()) {
                try {
                    processCommand(line);
                } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
                    System.err.println("Command execution error: " + e.getMessage());
                }
            }
        }
    }

    private void processCommand(String line) throws IOException, ClassNotFoundException, GeneralSecurityException {
        String[] parts = line.split(" ");
        String command = parts[0].toUpperCase();

        if ("EC".equals(command) && parts.length == 4) {
            handleEcCommand(parts);
            return;
        }

        if ("RH".equals(command) && parts.length >= 3) {
            parts[2] = parts[2].toUpperCase();
            line = String.join(" ", parts);
        }
        
        outStream.writeObject(line);

        if ("CREATE".equals(command) && parts.length >= 2) {
            handleCreateKeys();
        }

        outStream.flush();

        if ("RT".equals(command)) {
            receiveFile(buildRtFilename(parts));
        } else if ("RH".equals(command)) {
            receiveFile(buildRhFilename(parts));
        } else if ("ADD".equals(command) && parts.length >= 4) {
            handleAddResponse(parts[1]);
        } else {
            Object response = inStream.readObject();
            System.out.println(SERVER_PREFIX + response);
        }
    }

    private void handleEcCommand(String[] parts) throws IOException, ClassNotFoundException, GeneralSecurityException {
        String hm = parts[1];
        String d = parts[2].toUpperCase();
        String section = String.valueOf(d.charAt(0)).toUpperCase();

        int value;
        try {
            value = Integer.parseInt(parts[3]);
            if (value < 0 || value > 600) {
                System.out.println("Error: Value must be an integer between 0 and 600.");
                return;
            }
        } catch (NumberFormatException e) {
            System.out.println("Error: EC command requires an integer value.");
            return;
        }

        outStream.writeObject("GET_KEY " + hm + " " + section);
        outStream.flush();

        Object keyResp = inStream.readObject();
        if (!(keyResp instanceof byte[] wrappedKeyBytes)) {
            System.out.println("E2E Error: Failed to obtain section key. Server response: " + keyResp);
            return;
        }

        PrivateKey privKey = CryptoService.loadPrivateKey(keystorePath, keystorePassword.toCharArray(), username);
        SecretKey aesKey = CryptoService.unwrapKeyRSA(wrappedKeyBytes, privKey);

        byte[] encVal = CryptoService.encryptAES(String.valueOf(value), aesKey);
        String encValBase64 = Base64.getEncoder().encodeToString(encVal);

        outStream.writeObject("EC " + hm + " " + d + " " + encValBase64);
        outStream.flush();

        Object response = inStream.readObject();
        System.out.println(SERVER_PREFIX + response);
    }

    private void handleCreateKeys() throws IOException {
        try {
            Map<String, byte[]> wrappedKeys = ClientCryptoHelper.generateAndWrapSectionKeys(
                    username, keystorePath, keystorePassword);
            outStream.writeObject(wrappedKeys);
        } catch (Exception e) {
            System.err.println("Error generating section keys: " + e.getMessage());
            outStream.writeObject(Collections.emptyMap());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleAddResponse(String targetUser) throws IOException, ClassNotFoundException {
        Object resp = inStream.readObject();

        if (resp instanceof Object[] e2eData && e2eData.length >= 3 && "E2E_ADD".equals(e2eData[0])) {
            processE2eAdd(targetUser, (Map<String, byte[]>) e2eData[1], (byte[]) e2eData[2]);
        } else if (resp instanceof String serverMsg) {
            System.out.println(SERVER_PREFIX + serverMsg);
        } else if (resp == null) {
            System.out.println(SERVER_PREFIX + "Received null response");
        } else {
            System.out.println(SERVER_PREFIX + resp);
        }
    }

    private void processE2eAdd(String targetUser, Map<String, byte[]> keysToWrap, byte[] targetCertBytes)
            throws IOException, ClassNotFoundException {
        String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String trustStorePass = System.getProperty("javax.net.ssl.trustStorePassword");

        try {
            ClientCryptoHelper.saveCertificateToTrustStore(trustStorePath, trustStorePass, targetUser, targetCertBytes);
            System.out.println("[TRUST] Certificate for " + targetUser + " saved to truststore.");
        } catch (Exception e) {
            System.err.println("[TRUST] Error storing certificate into truststore: " + e.getMessage());
        }

        try {
            Map<String, byte[]> rewrappedKeys = ClientCryptoHelper.rewrapSectionKeys(
                    keysToWrap, targetCertBytes, username, keystorePath, keystorePassword);
            outStream.writeObject(rewrappedKeys);
            outStream.flush();

            String finalResp = (String) inStream.readObject();
            System.out.println(SERVER_PREFIX + finalResp);
        } catch (Exception e) {
            System.err.println("Failed to re-wrap keys: " + e.getMessage());
            outStream.writeObject(Collections.emptyMap());
            outStream.flush();
        }
    }

    @SuppressWarnings("unchecked")
    private void receiveFile(String localFilename) throws IOException, ClassNotFoundException, GeneralSecurityException {
        Object responseObj = inStream.readObject();
        String responseStatus = null;
        Map<String, byte[]> wrappedKeysMap = null;

        if (responseObj instanceof String statusStr) {
            responseStatus = statusStr;
        } else if (responseObj instanceof Object[] data) {
            responseStatus = (String) data[0];
            wrappedKeysMap = (Map<String, byte[]>) data[1];
        }

        if (!"OK".equals(responseStatus)) {
            System.out.println(SERVER_PREFIX + responseStatus);
            return;
        }

        long fileSize = (Long) inStream.readObject();
        byte[] data = inStream.readNBytes((int) fileSize);
        String contentStr = new String(data, StandardCharsets.UTF_8);

        Map<String, SecretKey> aesKeys = unwrapAllReceivedKeys(wrappedKeysMap);
        String decryptedContent = decryptFileContent(contentStr, aesKeys);

        Path targetPath = Paths.get(localFilename);
        if (targetPath.getParent() != null) {
            Files.createDirectories(targetPath.getParent());
        }

        Files.write(targetPath, decryptedContent.getBytes(StandardCharsets.UTF_8));
        System.out.println("File saved: " + targetPath);
        System.out.println("--- Content ---");
        System.out.println(decryptedContent);
        System.out.println("---------------");



    }

    private Map<String, SecretKey> unwrapAllReceivedKeys(Map<String, byte[]> wrappedKeysMap)
            throws IOException, GeneralSecurityException {
        Map<String, SecretKey> aesKeys = new HashMap<>();
        if (wrappedKeysMap == null) {
            return aesKeys;
        }

        PrivateKey privKey = CryptoService.loadPrivateKey(keystorePath, keystorePassword.toCharArray(), username);
        for (Map.Entry<String, byte[]> entry : wrappedKeysMap.entrySet()) {
            try {
                SecretKey aesKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
                aesKeys.put(entry.getKey(), aesKey);
            } catch (GeneralSecurityException e) {
                System.err.println("Failed to unwrap section key " + entry.getKey() + ": " + e.getMessage());
            }
        }
        return aesKeys;
    }

    private String decryptFileContent(String content, Map<String, SecretKey> aesKeys) {
        StringBuilder sb = new StringBuilder();
        try (Scanner sc = new Scanner(content)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine().trim();
                if (!line.isEmpty()) {
                    sb.append(decryptLine(line, aesKeys)).append("\n");
                }
            }
        }
        return sb.toString();
    }

    private String decryptLine(String line, Map<String, SecretKey> aesKeys) {
        if (line.contains(",") && !line.startsWith("device,value")) {
            String[] parts = line.split(",");
            if (parts.length >= 3) {
                parts[1] = decryptValueIfPossible(parts[0], parts[1], aesKeys);
                return String.join(",", parts);
            }
        } else if (line.contains(":")) {
            String[] parts = line.split(":");
            if (parts.length >= 2) {
                return parts[0] + ":" + decryptValueIfPossible(parts[0], parts[1], aesKeys);
            }
        }
        return line;
    }

    private String decryptValueIfPossible(String devId, String value, Map<String, SecretKey> aesKeys) {
        String sec = String.valueOf(devId.charAt(0)).toUpperCase();
        SecretKey k = aesKeys.get(sec);
        if (k != null && isBase64(value.trim())) {
            try {
                byte[] dec = Base64.getDecoder().decode(value.trim());
                return CryptoService.decryptAES(dec, k);
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                return value;
            }
        }
        return value;
    }

    private boolean isBase64(String s) {
        try {
            Base64.getDecoder().decode(s);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String buildRtFilename(String[] parts) {
        String house = (parts.length >= 2) ? parts[1] : "house";
        return Paths.get("RT", "rt_" + house + ".txt").toString();
    }

    private String buildRhFilename(String[] parts) {
        String house = (parts.length >= 2) ? parts[1] : "house";
        String device = (parts.length >= 3) ? parts[2].toUpperCase() : "device";
        return Paths.get("RH", "rh_" + house + "_" + device + ".csv").toString();
    }

    private void printBanner() {
        System.out.println("""

                ╔═════════════════════════════════════════════════════════════════════════════╗
                ║                          SMART HOME CONTROL PANEL                           ║
                ╠════════════════════╦════════════════════════════════════════════════════════╣
                ║ COMMAND            ║ DESCRIPTION                                            ║
                ╠════════════════════╬════════════════════════════════════════════════════════╣
                ║ CREATE <hm>        ║ Create a new house profile.                            ║
                ║ ADD <u1> <hm> <s>  ║ Add user <u1> to house <hm>, section <s>.              ║
                ║ RD <hm> <s>        ║ Register a new device in a specific section.           ║
                ║ EC <hm> <d> <v>    ║ Send state/timer value to the server.                  ║
                ║ RT <hm>            ║ Get the latest status of all devices in house.         ║
                ║ RH <hm> <d>        ║ Retrieve device history logs (.csv).                   ║
                ╚════════════════════╩════════════════════════════════════════════════════════╝
                 > Enter command or press Ctrl+C to exit.""");
    }
}