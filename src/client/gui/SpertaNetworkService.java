package client.gui;

import client.ClientCryptoHelper;
import client.KeystoreManager;
import javafx.collections.ObservableList;

import java.awt.Desktop;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SpertaNetworkService {

    private static final Logger LOGGER = Logger.getLogger(SpertaNetworkService.class.getName());
    private static final String TLS_PROTOCOL = "TLSv1.3";

    private SSLContext sslContext;
    private String currentUsername;
    private char[] currentSessionPassword;
    private String host = "localhost";
    private int port = 22345;

    private SSLSocket sslSocket;
    private BufferedReader in;
    private PrintWriter out;

    public void setConnectionEndpoint(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public synchronized void initializeSecurity(String username, char[] sessionPassword)
            throws GeneralSecurityException, IOException {
        this.currentUsername = username;
        this.currentSessionPassword = sessionPassword.clone();

        char[] derivedKsPass = KeystoreManager.deriveKeystorePassword(username, sessionPassword);
        KeyStore keyStore = KeystoreManager.loadClientKeystoreAutomatically(username, sessionPassword);
        KeyStore trustStore = KeystoreManager.loadTruststoreAutomatically(username);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, derivedKsPass);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        this.sslContext = SSLContext.getInstance(TLS_PROTOCOL);
        this.sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    public String registerUserOnServer(String targetHost, int targetPort, String username, String password) throws IOException {
        try {
            KeyStore trustStore = KeystoreManager.loadTruststoreAutomatically(username);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext regContext = SSLContext.getInstance(TLS_PROTOCOL);
            regContext.init(null, tmf.getTrustManagers(), null);

            try (SSLSocket regSocket = (SSLSocket) regContext.getSocketFactory().createSocket(targetHost, targetPort);
                 BufferedReader regIn = new BufferedReader(new InputStreamReader(regSocket.getInputStream(), StandardCharsets.UTF_8));
                 PrintWriter regOut = new PrintWriter(new OutputStreamWriter(regSocket.getOutputStream(), StandardCharsets.UTF_8), true)) {

                regSocket.startHandshake();
                regOut.println("REGISTER " + username + " " + password);

                String response = regIn.readLine();
                if (response == null) {
                    throw new IOException("Server closed connection without responding.");
                }
                return response;
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to establish secure TLS connection for registration: " + e.getMessage(), e);
        }
    }

    public String registerUserCertificate(String targetHost, int targetPort, String username,
                                           byte[] certificateBytes) throws IOException {
        try {
            KeyStore trustStore = KeystoreManager.loadTruststoreAutomatically(username);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext regContext = SSLContext.getInstance(TLS_PROTOCOL);
            regContext.init(null, tmf.getTrustManagers(), null);

            try (SSLSocket regSocket = (SSLSocket) regContext.getSocketFactory().createSocket(targetHost, targetPort);
                 BufferedReader regIn = new BufferedReader(new InputStreamReader(regSocket.getInputStream(), StandardCharsets.UTF_8));
                 PrintWriter regOut = new PrintWriter(new OutputStreamWriter(regSocket.getOutputStream(), StandardCharsets.UTF_8), true)) {
                regSocket.startHandshake();
                regOut.println("REGISTER_CERT " + username + " "
                        + Base64.getEncoder().encodeToString(certificateBytes));
                String response = regIn.readLine();
                if (response == null) {
                    throw new IOException("Server closed connection without responding.");
                }
                return response;
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to establish secure TLS connection for certificate registration: "
                    + e.getMessage(), e);
        }
    }

    private synchronized void ensureConnected() throws IOException {
        if (sslContext == null) {
            throw new IllegalStateException("Security context not initialized. Please log in first.");
        }

        if (sslSocket == null || sslSocket.isClosed() || !sslSocket.isConnected()) {
            SSLSocketFactory factory = sslContext.getSocketFactory();
            sslSocket = (SSLSocket) factory.createSocket(host, port);
            
            // Force the TLS handshake immediately so client certificates are sent to the server
            sslSocket.startHandshake();

            in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8), true);
        }
    }

    public synchronized List<String> fetchAccessibleHouses() throws IOException {
        ensureConnected();
        out.println("LIST_HOUSES");

        List<String> houses = new ArrayList<>();
        String line;
        while ((line = in.readLine()) != null) {
            if ("END_HOUSES".equalsIgnoreCase(line) || line.startsWith("END")) {
                break;
            }
            if (line.startsWith("ERROR")) {
                throw new IOException("Failed to fetch houses: " + line);
            }
            if (!line.trim().isEmpty()) {
                houses.add(line.trim());
            }
        }

        for (String house : new ArrayList<>(houses)) {
            ensureHouseKeys(house);
        }
        return houses;
    }

    private void ensureHouseKeys(String houseName) throws IOException {
        try {
            String ksPath = "keystores/users/keystore." + currentUsername;
            char[] password = KeystoreManager.deriveKeystorePassword(
                    currentUsername, currentSessionPassword);
            Map<String, byte[]> keys = ClientCryptoHelper.generateAndWrapSectionKeys(
                    currentUsername, ksPath, new String(password));

            StringBuilder payload = new StringBuilder();
            for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
                if (!payload.isEmpty()) {
                    payload.append(";");
                }
                payload.append(entry.getKey())
                       .append("=")
                       .append(Base64.getEncoder().encodeToString(entry.getValue()));
            }

            out.println("ENSURE_HOUSE_KEYS " + houseName + " " + payload);
            String response = in.readLine();
            if (response == null) {
                throw new IOException("Server closed connection while initializing house keys.");
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Could not initialize keys for house " + houseName, e);
        }
    }

    public synchronized List<DeviceViewModel> fetchDevicesStatus(String houseId) throws IOException {
        ensureConnected();
        out.println("GET_STATUS " + houseId);

        List<DeviceViewModel> devices = new ArrayList<>();
        String line;
        while ((line = in.readLine()) != null) {
            if ("END_STATUS".equalsIgnoreCase(line) || line.startsWith("END")) {
                break;
            }
            if (line.startsWith("ERROR")) {
                throw new IOException("Failed to fetch device status: " + line);
            }

            int separator = line.indexOf(':');
            if (separator != -1) {
                String devId = line.substring(0, separator).trim();
                String val = line.substring(separator + 1).trim();
                devices.add(new DeviceViewModel(devId, val));
            }
        }
        return devices;
    }

    public synchronized String createHouse(String houseName) throws GeneralSecurityException, IOException {
        ensureConnected();

        String ksPath = "keystores/users/keystore." + currentUsername;
        char[] derivedKsPass = KeystoreManager.deriveKeystorePassword(currentUsername, currentSessionPassword);

        Map<String, byte[]> wrappedSectionKeys = ClientCryptoHelper.generateAndWrapSectionKeys(
                currentUsername,
                ksPath,
                new String(derivedKsPass)
        );

        StringBuilder keysPayload = new StringBuilder();
        for (Map.Entry<String, byte[]> entry : wrappedSectionKeys.entrySet()) {
            if (!keysPayload.isEmpty()) {
                keysPayload.append(";");
            }
            keysPayload.append(entry.getKey())
                       .append("=")
                       .append(Base64.getEncoder().encodeToString(entry.getValue()));
        }

        out.println("CREATE_HOUSE " + houseName + " " + keysPayload);
        String response = in.readLine();
        if (response == null) {
            throw new IOException("Server closed connection without responding.");
        }
        return response;
    }

    public synchronized String addUserAccess(String houseId, String targetUsername, String targetSection)
            throws GeneralSecurityException, IOException {
        ensureConnected();

        out.println("GET_USER_CERT " + targetUsername);
        String certResponse = in.readLine();
        if (certResponse == null || certResponse.startsWith("ERROR")) {
            throw new IOException("Target user certificate could not be retrieved: " + certResponse);
        }

        byte[] targetCertBytes = Base64.getDecoder().decode(certResponse);

        out.println("GET_SECTION_KEYS " + houseId + " " + targetSection);
        String wrappedKeyLine = in.readLine();
        if (wrappedKeyLine == null || wrappedKeyLine.startsWith("ERROR")) {
            throw new IOException("Failed to retrieve current section keys: " + wrappedKeyLine);
        }

        Map<String, byte[]> rawKeys = new HashMap<>();
        rawKeys.put(targetSection, Base64.getDecoder().decode(wrappedKeyLine));

        String ksPath = "keystores/users/keystore." + currentUsername;
        char[] derivedKsPass = KeystoreManager.deriveKeystorePassword(currentUsername, currentSessionPassword);

        Map<String, byte[]> rewrapped = ClientCryptoHelper.rewrapSectionKeys(
                rawKeys,
                targetCertBytes,
                ksPath,
                new String(derivedKsPass),
                currentUsername
        );

        byte[] newWrappedKey = rewrapped.get(targetSection);
        String b64NewKey = Base64.getEncoder().encodeToString(newWrappedKey);

        out.println("GRANT_ACCESS " + houseId + " " + targetUsername + " " + targetSection + " " + b64NewKey);
        String ack = in.readLine();
        return (ack != null) ? ack : "ERROR: No response from server";
    }

    public synchronized String registerDevice(String houseId, String deviceId) throws IOException {
        ensureConnected();
        out.println("REGISTER_DEVICE " + houseId + " " + deviceId);

        String response = in.readLine();
        if (response == null) {
            throw new IOException("Server closed connection without responding.");
        }
        return response;
    }

    public synchronized String executeCommand(String houseId, String deviceId, int durationMinutes) throws IOException {
        ensureConnected();
        out.println("EXECUTE_COMMAND " + houseId + " " + deviceId + " " + durationMinutes);

        String response = in.readLine();
        if (response == null) {
            throw new IOException("Server closed connection without responding.");
        }
        return response;
    }

    public synchronized File saveStatusToFile(String houseId, ObservableList<DeviceViewModel> devices) throws IOException {
        File directory = new File("RT");
        if (!directory.exists() && !directory.mkdirs()) {
            throw new IOException("Could not create RT directory: " + directory.getAbsolutePath());
        }

        String safeUser = currentUsername != null ? currentUsername : "unknown";
        String safeHouse = houseId != null ? houseId : "house";
        File file = new File(directory, safeUser + "_" + safeHouse + "_status.txt");

        try (FileWriter fw = new FileWriter(file, StandardCharsets.UTF_8);
             PrintWriter pw = new PrintWriter(fw)) {

            pw.println("User: " + safeUser + ", House: " + safeHouse);

            if (devices != null) {
                for (DeviceViewModel dev : devices) {
                    String timestamp = LocalDateTime.ofInstant(
                            java.time.Instant.ofEpochMilli(dev.getLastCommandTimestamp()),
                            java.time.ZoneId.systemDefault())
                            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                    pw.println(dev.getDeviceId() + ": " + dev.getValue() + ", " + timestamp);
                }
            }
        }
        return file;
    }

    private Path createSecureTempFile(String prefix, String suffix) throws IOException {
        Path appTempDir = Paths.get(System.getProperty("user.dir"), "target", "temp");
        Files.createDirectories(appTempDir);
        return Files.createTempFile(appTempDir, prefix, suffix);
    }

    public synchronized File fetchDeviceHistory(String houseId, String deviceId) throws IOException {
        ensureConnected();
        out.println("GET_DEVICE_HISTORY " + houseId + " " + deviceId);

        Path tempPath = createSecureTempFile("history_" + deviceId + "_", ".csv");
        File tempFile = tempPath.toFile();
        tempFile.deleteOnExit();

        try (BufferedWriter writer = Files.newBufferedWriter(tempPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if ("END_HISTORY".equalsIgnoreCase(line) || line.startsWith("END")) {
                    break;
                }
                if (line.startsWith("ERROR")) {
                    throw new IOException("Failed to fetch device history: " + line);
                }
                writer.write(line);
                writer.newLine();
            }
        }

        return tempFile;
    }

    public synchronized void disconnect() {
        try {
            if (out != null) {
                out.close();
            }
        } catch (Exception ex) {
            LOGGER.log(Level.FINE, "Error closing stream writer", ex);
        } finally {
            out = null;
        }

        try {
            if (in != null) {
                in.close();
            }
        } catch (Exception ex) {
            LOGGER.log(Level.FINE, "Error closing stream reader", ex);
        } finally {
            in = null;
        }

        try {
            if (sslSocket != null && !sslSocket.isClosed()) {
                sslSocket.close();
            }
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "Error closing SSL socket", ex);
        } finally {
            sslSocket = null;
        }
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public String getCurrentUsername() {
        return currentUsername;
    }
}