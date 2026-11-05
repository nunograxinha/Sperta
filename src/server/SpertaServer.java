package server;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Base64;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class SpertaServer {

    private static final Logger LOGGER = Logger.getLogger(SpertaServer.class.getName());
    private static final Object STORAGE_LOCK = new Object();
    private static final String INVALID_PARAMETERS = "ERROR: Invalid parameters";
    private static final String HOUSE_NOT_FOUND = "ERROR: House not found";
    private static final String UNAUTHORIZED_SECTION = "ERROR: Unauthorized access to section ";

    static {
        configureLogging();
    }

    private static void configureLogging() {
        Logger rootLogger = Logger.getLogger("");
        for (Handler handler : rootLogger.getHandlers()) {
            rootLogger.removeHandler(handler);
        }
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setFormatter(new SpertaLogFormatter());
        consoleHandler.setLevel(Level.ALL);
        rootLogger.addHandler(consoleHandler);
        rootLogger.setLevel(Level.ALL);
    }

    private static class SpertaLogFormatter extends Formatter {
        private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        @Override
        public String format(LogRecord logRecord) {
            String timestamp = LocalDateTime.now(ZoneId.systemDefault()).format(FORMATTER);
            String level = logRecord.getLevel().getName();
            String message = formatMessage(logRecord);
            return String.format("[%s] [%s] %s%n", timestamp, level, message);
        }
    }

    public static void main(String[] args) {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 22345;
        String serverPassword = args.length > 1 ? args[1] : "server-pw";
        String keystorePath = args.length > 2 ? args[2] : "keystores/keystore.server";
        String storagePassword = args.length > 3 ? args[3] : "123456";

        try {
            StorageDAO storageDAO = new StorageDAO(storagePassword);
            ScheduledExecutorService expirationMonitor = startExpirationMonitor(storageDAO);

            SSLContext sslContext = createSSLContext(keystorePath, serverPassword);
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

            try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port)) {
                // Registration is performed before the client has a certificate.
                // Authenticated commands still require one in ServerThread.
                serverSocket.setWantClientAuth(true);

                if (LOGGER.isLoggable(Level.INFO)) {
                    LOGGER.log(Level.INFO, "Sperta IoT Server listening on port {0} (TLS 1.3)...", String.valueOf(port));
                }

                while (!Thread.currentThread().isInterrupted()) {
                    Socket clientSocket = serverSocket.accept();
                    if (LOGGER.isLoggable(Level.INFO)) {
                        LOGGER.log(Level.INFO, "New secured client connected: {0}", clientSocket.getRemoteSocketAddress());
                    }
                    new ServerThread((SSLSocket) clientSocket, storageDAO).start();
                }
            }
            finally {
                expirationMonitor.shutdownNow();
            }

        } catch (IOException | GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Server encountered a fatal error", e);
        }
    }

    private static ScheduledExecutorService startExpirationMonitor(StorageDAO storage) {
        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sperta-device-expiration-monitor");
            thread.setDaemon(true);
            return thread;
        });
        monitor.scheduleAtFixedRate(
                () -> expireDevices(storage),
                1,
                1,
                TimeUnit.SECONDS);
        return monitor;
    }

    private static void expireDevices(StorageDAO storage) {
        File homesDir = new File("data/homes");
        File[] files = homesDir.listFiles((dir, name) -> name.endsWith(".txt"));
        if (files == null) {
            return;
        }

        for (File file : files) {
            String houseName = file.getName().substring(0, file.getName().length() - 4);
            try {
                synchronized (STORAGE_LOCK) {
                    expireHouseDevices(storage, houseName);
                }
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.log(Level.WARNING, e, () -> "Could not expire devices in house " + houseName);
            }
        }
    }

    private static void expireHouseDevices(StorageDAO storage, String houseName)
            throws IOException, GeneralSecurityException {
        House house = storage.loadHouse(houseName);
        if (house == null) {
            return;
        }

        boolean houseChanged = false;
        for (House.Section section : house.getSections().values()) {
            for (Map.Entry<String, String> device : section.getDevices().entrySet()) {
                houseChanged |= expireDevice(storage, houseName, section, device);
            }
        }
        if (houseChanged) {
            storage.saveHouse(house);
        }
    }

    private static boolean expireDevice(
            StorageDAO storage, String houseName, House.Section section, Map.Entry<String, String> device)
            throws IOException {
        String[] stateParts = device.getValue().split("@", 2);
        if (stateParts.length != 2) {
            return false;
        }

        try {
            int minutes = Integer.parseInt(stateParts[0]);
            long startedAt = Long.parseLong(stateParts[1]);
            long expiresAt = startedAt + minutes * 60_000L;
            if (minutes > 1 && System.currentTimeMillis() >= expiresAt) {
                section.setDeviceValue(device.getKey(), "0");
                storage.appendDeviceLog(houseName, device.getKey(), "0");
                return true;
            }
        } catch (NumberFormatException ignored) {
            // Preserve malformed legacy state for explicit correction.
        }
        return false;
    }

    private static SSLContext createSSLContext(String keystorePath, String serverPassword)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        String[] candidatePasswords = {serverPassword, "123456"};
        char[] activePassword = null;

        for (String pwd : candidatePasswords) {
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, pwd.toCharArray());
                activePassword = pwd.toCharArray();
                break;
            } catch (IOException | GeneralSecurityException ignored) {
                // Try next candidate password
            }
        }

        if (activePassword == null) {
            throw new IOException("Failed to load server keystore: password was incorrect.");
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, activePassword);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), new X509TrustManager[]{new ClientCertificateTrustManager()}, null);
        return sslContext;
    }

    /**
     * User certificates are self-signed and are identified by their subject
     * after the TLS handshake. Returning no issuer constraints makes JSSE send
     * those certificates during optional client authentication.
     */
    private static final class ClientCertificateTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            if (chain == null || chain.length == 0) {
                throw new IllegalArgumentException("Client certificate chain is empty");
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            if (chain == null || chain.length == 0) {
                throw new IllegalArgumentException("Server certificate chain is empty");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static class ServerThread extends Thread {
        private final SSLSocket sslSocket;
        private final StorageDAO storage;

        public ServerThread(SSLSocket sslSocket, StorageDAO storage) {
            this.sslSocket = sslSocket;
            this.storage = storage;
        }

        @Override
        public void run() {
            try (
                BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter out = new PrintWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8), true)
            ) {
                String line = in.readLine();
                if (line == null) {
                    return;
                }

                if (line.startsWith("REGISTER ")) {
                    handleRegistration(line, out);
                    return;
                }
                if (line.startsWith("REGISTER_CERT ")) {
                    handleCertificateRegistration(line, out);
                    return;
                }

                Certificate[] clientCerts = verifyClientCertificates(out);
                if (clientCerts.length == 0) {
                    return;
                }

                if (!authenticateClient(line, out, clientCerts)) {
                    return;
                }

                line = in.readLine();
                while (line != null) {
                    processAuthenticatedCommand(line, out, clientCerts);
                    line = in.readLine();
                }

            } catch (IOException e) {
                if (LOGGER.isLoggable(Level.FINE)) {
                    LOGGER.log(Level.FINE, "Client connection terminated: {0}", e.getMessage());
                }
            } finally {
                closeSocketSilently();
            }
        }

        private Certificate[] verifyClientCertificates(PrintWriter out) {
            try {
                Certificate[] clientCerts = sslSocket.getSession().getPeerCertificates();
                if (clientCerts == null || clientCerts.length == 0) {
                    if (LOGGER.isLoggable(Level.INFO)) {
                        LOGGER.info("Connection closed for client: unauthenticated");
                    }
                    out.println("ERROR: Client certificate required");
                    return new X509Certificate[0];
                }
                return clientCerts;
            } catch (SSLPeerUnverifiedException e) {
                if (LOGGER.isLoggable(Level.INFO)) {
                    LOGGER.info("Connection closed for client: unauthenticated");
                }
                out.println("ERROR: Client certificate required");
                return new X509Certificate[0];
            }
        }

        private boolean authenticateClient(String line, PrintWriter out, Certificate[] clientCerts) {
            String[] tokens = line.trim().split("\\s+", 3);
            if (tokens.length < 3 || !"AUTH".equals(tokens[0])) {
                out.println("ERROR: Authentication required");
                return false;
            }

            String username = tokens[1];
            String certificateUsername = extractUsernameFromDn(
                    ((X509Certificate) clientCerts[0]).getSubjectX500Principal().getName());
            if (!certificateUsername.equals(username)) {
                out.println("ERROR: Certificate does not match username");
                return false;
            }

            try {
                if (storage.authenticateUser(username, tokens[2]) != 1) {
                    out.println("ERROR: Invalid username or password");
                    return false;
                }
                out.println("OK:AUTHENTICATED");
                return true;
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.log(Level.WARNING, "Authentication failed for user {0}", username);
                out.println("ERROR: Authentication failed");
                return false;
            }
        }

        private void handleRegistration(String command, PrintWriter out) {
            String[] tokens = command.trim().split("\\s+");
            if (tokens.length < 3) {
                out.println("ERROR: Invalid registration format. Expected: REGISTER <username> <password>");
                return;
            }

            String username = tokens[1];
            String password = tokens[2];

            try {
                if (storage.userExists(username)) {
                    if (LOGGER.isLoggable(Level.WARNING)) {
                        LOGGER.log(Level.WARNING, "Registration failed: user already exists: {0}", username);
                    }
                    out.println("ERROR: User already exists");
                    return;
                }

                boolean registered = storage.registerNewUser(username, password, null);
                if (registered) {
                    if (LOGGER.isLoggable(Level.INFO)) {
                        LOGGER.log(Level.INFO, "Successfully registered user: {0}", username);
                    }
                    out.println("OK:USER_REGISTERED");
                } else {
                    out.println("ERROR: Could not complete registration");
                }
            } catch (RuntimeException ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Internal error during registration for user " + username);
                out.println("ERROR: Server registration failure: " + ex.getMessage());
            }
        }

        private void handleCertificateRegistration(String command, PrintWriter out) {
            String[] tokens = command.trim().split("\\s+", 3);
            if (tokens.length < 3) {
                out.println("ERROR: Invalid certificate registration format");
                return;
            }

            try {
                storage.saveUserCertificate(tokens[1], Base64.getDecoder().decode(tokens[2]));
                out.println("OK:CERTIFICATE_STORED");
            } catch (IllegalArgumentException | IOException ex) {
                LOGGER.log(Level.WARNING, ex, () -> "Could not store certificate for user " + tokens[1]);
                out.println("ERROR: Could not store certificate");
            }
        }

        private void processAuthenticatedCommand(
                String line, PrintWriter out, Certificate[] clientCerts) {
            try {
                String username = authenticatedUsername(clientCerts);
                String command = line.split("\\s+", 2)[0];
                switch (command) {
                    case "LIST_HOUSES" -> listHouses(out, username);
                    case "GET_STATUS" -> getStatus(line, out, username);
                    case "CREATE_HOUSE" -> createHouse(line, out, username);
                    case "ENSURE_HOUSE_KEYS" -> ensureHouseKeys(line, out, username);
                    case "REGISTER_DEVICE" -> registerDevice(line, out, username);
                    case "EXECUTE_COMMAND" -> executeCommand(line, out, username);
                    case "GET_USER_CERT" -> getUserCertificate(line, out);
                    case "GET_SECTION_KEYS" -> getSectionKeys(line, out, username);
                    case "GRANT_ACCESS" -> grantAccess(line, out, username);
                    case "GET_DEVICE_HISTORY" -> getDeviceHistory(line, out);
                    default -> out.println("ERROR: Unknown command: " + line);
                }
            } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
                LOGGER.log(Level.WARNING, "Command execution failed: {0}", e.getMessage());
                out.println("ERROR: " + e.getMessage());
            }
        }

        private String authenticatedUsername(Certificate[] clientCerts) {
            String clientDn = ((X509Certificate) clientCerts[0]).getSubjectX500Principal().getName();
            return extractUsernameFromDn(clientDn);
        }

        private void listHouses(PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            File homesDir = new File("data/homes");
            File[] files = homesDir.listFiles((dir, name) -> name.endsWith(".txt"));
            if (files != null) {
                for (File file : files) {
                    String houseName = file.getName().replace(".txt", "");
                    House house = storage.loadHouse(houseName);
                    if (house != null && house.hasAccess(username)) {
                        out.println(houseName);
                    }
                }
            }
            out.println("END_HOUSES");
        }

        private void getStatus(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            synchronized (STORAGE_LOCK) {
                String houseId = line.substring("GET_STATUS ".length()).trim();
                House house = storage.loadHouse(houseId);
                if (house != null) {
                    boolean changed = expireDevices(house, houseId, out, username);
                    if (changed) {
                        storage.saveHouse(house);
                    }
                }
                out.println("END_STATUS");
            }
        }

        private boolean expireDevices(House house, String houseId, PrintWriter out, String username)
                throws IOException {
            boolean changed = false;
            for (Map.Entry<String, House.Section> entry : house.getSections().entrySet()) {
                if (!house.isAuthorized(username, entry.getKey())) {
                    continue;
                }
                for (Map.Entry<String, String> device : entry.getValue().getDevices().entrySet()) {
                    String previousState = device.getValue();
                    String state = expireDevice(houseId, entry.getValue(), device);
                    out.println(device.getKey() + ":" + state);
                    changed |= !previousState.equals(state);
                }
            }
            return changed;
        }

        private String expireDevice(String houseId, House.Section section, Map.Entry<String, String> device)
                throws IOException {
            String state = device.getValue();
            String[] parts = state.split("@", 2);
            if (parts.length == 2) {
                try {
                    int minutes = Integer.parseInt(parts[0]);
                    long expiresAt = Long.parseLong(parts[1]) + minutes * 60_000L;
                    if (minutes > 1 && System.currentTimeMillis() >= expiresAt) {
                        section.setDeviceValue(device.getKey(), "0");
                        storage.appendDeviceLog(houseId, device.getKey(), "0");
                        return "0";
                    }
                } catch (NumberFormatException ignored) {
                    // Preserve malformed legacy state for explicit correction.
                }
            }
            return section.getDevices().get(device.getKey());
        }

        private void createHouse(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+", 3);
            if (parts.length < 2) {
                out.println(INVALID_PARAMETERS);
                return;
            }
            String houseName = parts[1];
            if (storage.houseExists(houseName)) {
                out.println("ERROR: House already exists");
                return;
            }
            storage.saveHouse(new House(houseName, username));
            if (parts.length == 3) {
                saveSectionKeys(parts[2], houseName, username);
            }
            out.println("OK:HOUSE_CREATED");
        }

        private void saveSectionKeys(String encodedKeys, String houseName, String username)
                throws IOException {
            for (String keyEntry : encodedKeys.split(";")) {
                String[] keyParts = keyEntry.split("=", 2);
                if (keyParts.length == 2) {
                    storage.saveSectionKey(
                            houseName, keyParts[0], username, Base64.getDecoder().decode(keyParts[1]));
                }
            }
        }

        private void ensureHouseKeys(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+", 3);
            if (parts.length != 3) {
                out.println("ERROR: Invalid house key request");
                return;
            }
            House house = storage.loadHouse(parts[1]);
            if (house == null) {
                out.println(HOUSE_NOT_FOUND);
            } else if (!house.getOwner().equals(username)) {
                out.println("ERROR: Only the house owner can initialize keys");
            } else {
                saveMissingSectionKeys(parts[1], parts[2], username);
                out.println("OK:HOUSE_KEYS_READY");
            }
        }

        private void saveMissingSectionKeys(String houseName, String encodedKeys, String username)
                throws IOException {
            for (String keyEntry : encodedKeys.split(";")) {
                String[] keyParts = keyEntry.split("=", 2);
                if (keyParts.length == 2 && storage.loadSectionKey(houseName, keyParts[0], username) == null) {
                    storage.saveSectionKey(
                            houseName, keyParts[0], username, Base64.getDecoder().decode(keyParts[1]));
                }
            }
        }

        private void registerDevice(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+");
            if (parts.length < 3) {
                out.println(INVALID_PARAMETERS);
                return;
            }
            String houseName = parts[1];
            String sectionKey = String.valueOf(Character.toUpperCase(parts[2].charAt(0)));
            House house = storage.loadHouse(houseName);
            if (house == null) {
                out.println(HOUSE_NOT_FOUND);
                return;
            }
            if (!house.isAuthorized(username, sectionKey)) {
                out.println(UNAUTHORIZED_SECTION + sectionKey);
                return;
            }
            House.Section section = house.getSection(sectionKey);
            if (section == null) {
                out.println("ERROR: Invalid section for device ID");
                return;
            }
            String deviceId = sectionKey + section.getNextDeviceId();
            section.setDeviceValue(deviceId, "0");
            storage.saveHouse(house);
            storage.appendDeviceLog(houseName, deviceId, "0");
            out.println("OK:DEVICE_REGISTERED:" + deviceId);
        }

        private void executeCommand(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+");
            if (parts.length != 4) {
                out.println(INVALID_PARAMETERS);
                return;
            }
            int minutes;
            try {
                minutes = Integer.parseInt(parts[3]);
            } catch (NumberFormatException ex) {
                out.println("ERROR: Invalid duration");
                return;
            }
            if (minutes < 0 || minutes > 600) {
                out.println("ERROR: Duration must be between 0 and 600");
                return;
            }
            String houseName = parts[1];
            String deviceId = parts[2];
            House house = storage.loadHouse(houseName);
            String sectionKey = deviceId.isEmpty()
                    ? ""
                    : String.valueOf(Character.toUpperCase(deviceId.charAt(0)));
            House.Section section = house == null ? null : house.getSection(sectionKey);
            if (house == null) {
                out.println(HOUSE_NOT_FOUND);
            } else if (!house.isAuthorized(username, sectionKey)) {
                out.println(UNAUTHORIZED_SECTION + sectionKey);
            } else if (section == null || !section.getDevices().containsKey(deviceId)) {
                out.println("ERROR: Device not found");
            } else {
                section.setDeviceValue(deviceId, minutes + "@" + System.currentTimeMillis());
                storage.saveHouse(house);
                storage.appendDeviceLog(houseName, deviceId, String.valueOf(minutes));
                out.println("OK");
            }
        }

        private void getUserCertificate(String line, PrintWriter out) throws IOException {
            String[] parts = line.split("\\s+");
            if (parts.length != 2) {
                out.println("ERROR: Invalid user certificate request");
                return;
            }
            byte[] certificate = storage.getUserCertificate(parts[1]);
            if (certificate == null) {
                out.println("ERROR: User certificate not found");
            } else {
                out.println(Base64.getEncoder().encodeToString(certificate));
            }
        }

        private void getSectionKeys(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+");
            if (parts.length != 3) {
                out.println("ERROR: Invalid section key request");
                return;
            }
            String houseName = parts[1];
            String section = parts[2].toUpperCase();
            House house = storage.loadHouse(houseName);
            if (house == null) {
                out.println(HOUSE_NOT_FOUND);
            } else if (!house.isAuthorized(username, section)) {
                out.println(UNAUTHORIZED_SECTION + section);
            } else {
                byte[] key = storage.loadSectionKey(houseName, section, username);
                if (key == null) {
                    out.println("ERROR: Section key not found");
                } else {
                    out.println(Base64.getEncoder().encodeToString(key));
                }
            }
        }

        private void grantAccess(String line, PrintWriter out, String username)
                throws IOException, GeneralSecurityException {
            String[] parts = line.split("\\s+");
            if (parts.length != 5) {
                out.println("ERROR: Invalid access grant request");
                return;
            }
            House house = storage.loadHouse(parts[1]);
            String section = parts[3].toUpperCase();
            if (house == null) {
                out.println(HOUSE_NOT_FOUND);
            } else if (!house.getOwner().equals(username)) {
                out.println("ERROR: Only the house owner can grant access");
            } else if (house.getSection(section) == null) {
                out.println("ERROR: Invalid section");
            } else {
                storage.saveSectionKey(
                        parts[1], section, parts[2], Base64.getDecoder().decode(parts[4]));
                house.getSection(section).addUser(parts[2]);
                storage.saveHouse(house);
                out.println("OK:ACCESS_GRANTED");
            }
        }

        private void getDeviceHistory(String line, PrintWriter out)
                throws IOException {
            String[] parts = line.split("\\s+");
            if (parts.length < 3) {
                out.println(INVALID_PARAMETERS);
                return;
            }
            byte[] logBytes = storage.loadDeviceLog(parts[1], parts[2]);
            if (logBytes != null && logBytes.length > 0) {
                out.println(new String(logBytes, StandardCharsets.UTF_8));
            }
            out.println("END_HISTORY");
        }

        private String extractUsernameFromDn(String dn) {
            for (String part : dn.split(",")) {
                String trimmed = part.trim();
                if (trimmed.toUpperCase().startsWith("CN=")) {
                    return trimmed.substring(3).trim();
                }
            }
            return dn;
        }

        private void closeSocketSilently() {
            try {
                if (sslSocket != null && !sslSocket.isClosed()) {
                    sslSocket.close();
                }
            } catch (IOException ignored) {
                // Ignore exception on close
            }
        }
    }
}