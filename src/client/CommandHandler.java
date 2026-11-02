package client;

import utils.CryptoService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

/**
 * Handles the interactive terminal session, command parsing, E2E encryption dispatch,
 * and decryption of received server files (RT/RH).
 */
public class CommandHandler {

    private static final Logger LOGGER = Logger.getLogger(CommandHandler.class.getName());

    private final ObjectOutputStream outStream;
    private final ObjectInputStream inStream;
    private final Scanner scanner;
    private final String username;
    private final String keystorePath;
    private final String keystorePassword;

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
            LOGGER.log(Level.INFO, "> ");
            String line = scanner.nextLine().trim();
            if (!line.isEmpty()) {
                try {
                    processCommand(line);
                } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
                    LOGGER.log(Level.SEVERE, "Command execution error: {0}", e.getMessage());
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
            LOGGER.log(Level.INFO, "[SERVER]: {0}", response);
        }
    }

    private void handleEcCommand(String[] parts) throws IOException, ClassNotFoundException, GeneralSecurityException {
        String hm = parts[1];
        String d = parts[2];
        String section = String.valueOf(d.charAt(0)).toUpperCase();

        int value;
        try {
            value = Integer.parseInt(parts[3]);
            if (value < 0 || value > 600) {
                LOGGER.log(Level.WARNING, "Error: Value must be an integer between 0 and 600.");
                return;
            }
        } catch (NumberFormatException e) {
            LOGGER.log(Level.WARNING, "Error: EC command requires an integer value.");
            return;
        }

        outStream.writeObject("GET_KEY " + hm + " " + section);
        outStream.flush();

        Object keyResp = inStream.readObject();
        if (!(keyResp instanceof byte[] wrappedKeyBytes)) {
            LOGGER.log(Level.WARNING, "E2E Error: Failed to obtain section key. Server response: {0}", keyResp);
            return;
        }

        PrivateKey privKey = CryptoService.loadPrivateKey(keystorePath, keystorePassword.toCharArray(), username);
        SecretKey aesKey = CryptoService.unwrapKeyRSA(wrappedKeyBytes, privKey);

        byte[] encVal = CryptoService.encryptAES(String.valueOf(value), aesKey);
        String encValBase64 = Base64.getEncoder().encodeToString(encVal);

        outStream.writeObject("EC " + hm + " " + d + " " + encValBase64);
        outStream.flush();

        Object response = inStream.readObject();
        LOGGER.log(Level.INFO, "[SERVER]: {0}", response);
    }

    private void handleCreateKeys() throws IOException {
        try {
            Map<String, byte[]> wrappedKeys = ClientCryptoHelper.generateAndWrapSectionKeys(
                    username, keystorePath, keystorePassword);
            outStream.writeObject(wrappedKeys);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error generating section keys: {0}", e.getMessage());
            outStream.writeObject(Collections.emptyMap());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleAddResponse(String targetUser) throws IOException, ClassNotFoundException {
        Object resp = inStream.readObject();

        switch (resp) {
            case Object[] e2eData when e2eData.length >= 3 && "E2E_ADD".equals(e2eData[0]) ->
                processE2eAdd(targetUser, (Map<String, byte[]>) e2eData[1], (byte[]) e2eData[2]);

            case String serverMsg ->
                LOGGER.log(Level.INFO, "[SERVER]: {0}", serverMsg);

            case null ->
                LOGGER.log(Level.WARNING, "[SERVER]: Received null response");

            default ->
                LOGGER.log(Level.INFO, "[SERVER]: {0}", resp);
        }
    }

    private void processE2eAdd(String targetUser, Map<String, byte[]> keysToWrap, byte[] targetCertBytes)
            throws IOException, ClassNotFoundException {
        String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        String trustStorePass = System.getProperty("javax.net.ssl.trustStorePassword");

        try {
            ClientCryptoHelper.saveCertificateToTrustStore(trustStorePath, trustStorePass, targetUser, targetCertBytes);
            LOGGER.log(Level.INFO, "[TRUST] Certificate for {0} saved to truststore.", targetUser);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "[TRUST] Error storing certificate into truststore: {0}", e.getMessage());
        }

        try {
            Map<String, byte[]> rewrappedKeys = ClientCryptoHelper.rewrapSectionKeys(
                    keysToWrap, targetCertBytes, username, keystorePath, keystorePassword);
            outStream.writeObject(rewrappedKeys);
            outStream.flush();

            String finalResp = (String) inStream.readObject();
            LOGGER.log(Level.INFO, "[SERVER]: {0}", finalResp);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to re-wrap keys: {0}", e.getMessage());
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
            LOGGER.log(Level.WARNING, "[SERVER]: {0}", responseStatus);
            return;
        }

        long fileSize = (Long) inStream.readObject();
        byte[] data = inStream.readNBytes((int) fileSize);
        String contentStr = new String(data, StandardCharsets.UTF_8);

        Map<String, SecretKey> aesKeys = unwrapAllReceivedKeys(wrappedKeysMap);
        String decryptedContent = decryptFileContent(contentStr, aesKeys);

        Files.write(Paths.get(localFilename), decryptedContent.getBytes(StandardCharsets.UTF_8));
        LOGGER.log(Level.INFO, "File saved: {0}\n--- Content ---\n{1}\n---------------", 
                new Object[]{localFilename, decryptedContent});
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
                LOGGER.log(Level.SEVERE, "Failed to unwrap section key {0}: {1}", 
                        new Object[]{entry.getKey(), e.getMessage()});
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
        return "rt_" + house + ".txt";
    }

    private String buildRhFilename(String[] parts) {
        String house = (parts.length >= 2) ? parts[1] : "house";
        String device = (parts.length >= 3) ? parts[2] : "device";
        return "rh_" + house + "_" + device + ".csv";
    }

    private void printBanner() {
        LOGGER.log(Level.INFO, """

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