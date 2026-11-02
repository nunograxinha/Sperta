package server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.*;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import utils.CryptoService;

/**
 * Main TLS Server for the Sperta Smart Home ecosystem.
 * Coordinates remote binary attestation, client authentication, and network commands,
 * delegating persistence, concurrency, and integrity checks to StorageDAO and House.
 */
public class SpertaServer {

    private static final Logger LOGGER = Logger.getLogger(SpertaServer.class.getName());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Protocol Response Literals
    private static final String RESP_OK = "OK";
    private static final String RESP_NOK = "NOK";
    private static final String RESP_NO_PERM = "NOPERM";
    private static final String RESP_NO_HM = "NOHM";
    private static final String RESP_NO_DATA = "NODATA";
    private static final String RESP_NO_D = "NOD";
    private static final String RESP_NO_USER = "NOUSER";
    private static final String RESP_OK_ATTEST = "OK-ATTEST";
    private static final String RESP_NOK_ATTEST = "NOK-ATTEST";

    private StorageDAO storageDAO;
    private volatile boolean running = true;

    private static void setupLogging() {
        Locale.setDefault(Locale.ENGLISH);

        Logger rootLogger = Logger.getLogger("");
        Handler[] handlers = rootLogger.getHandlers();
        for (Handler handler : handlers) {
            rootLogger.removeHandler(handler);
        }

        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);
        consoleHandler.setFormatter(new java.util.logging.SimpleFormatter() {
            private final DateTimeFormatter dtf = TIME_FORMATTER;
            private final ZoneId zoneId = ZoneId.systemDefault();
            @Override
            public String format(LogRecord logRecord) {
                String timestamp = LocalDateTime.now(zoneId).format(dtf);
                String level = logRecord.getLevel().getName();
                String message = formatMessage(logRecord);
                return String.format("[%s] [%s] %s%n", timestamp, level, message);
            }
        });

        rootLogger.addHandler(consoleHandler);
        rootLogger.setLevel(Level.INFO);
    }

    public static void main(String[] args) {
        setupLogging();
        LOGGER.info("SpertaServer: main");
        SpertaServer server = new SpertaServer();
        server.startServer(args);
    }

    public void startServer(String[] args) {
        if (args.length != 4) {
            LOGGER.severe("Usage: java SpertaServer <port> <password-cifra> <keystore> <password-keystore>");
            System.exit(1);
        }

        int port = 22345;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            LOGGER.log(Level.SEVERE, e, () -> "Invalid argument: port must be an integer.");
            System.exit(1);
        }

        String cipherPassword = args[1];
        String keystorePath = args[2];
        String keystorePassword = args[3];

        try {
            this.storageDAO = new StorageDAO(cipherPassword);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, e, () -> "Failed to initialize StorageDAO engine: " + e.getMessage());
            System.exit(1);
        }

        // Configure system properties for SSL/TLS handshake
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);

        String referenceClientPath = loadExpectedClientPath();
        if (referenceClientPath == null) {
            LOGGER.warning("data/attestation.txt not found. Client attestation disabled.");
        } else {
            LOGGER.log(Level.INFO, "Attestation active with reference binary: {0}", referenceClientPath);
        }

        try {
            SSLServerSocketFactory sslSrvFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslSrvFact.createServerSocket(port)) {
                serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                final int serverPort = port;
                LOGGER.log(Level.INFO, () -> "Server started on port " + serverPort + " (TLS)");
                while (running && !serverSocket.isClosed() && !Thread.currentThread().isInterrupted()) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    LOGGER.log(Level.INFO, "New secured client connected: {0}", clientSocket.getInetAddress());
                    new ServerThread(clientSocket, referenceClientPath).start();
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, e, () -> "Server socket encountered an error: " + e.getMessage());
        }
    }

    public void stopServer() {
        this.running = false;
    }

    private String loadExpectedClientPath() {
        Path filePath = Paths.get("data", "attestation.txt");
        if (!Files.exists(filePath)) {
            return null;
        }

        try (Scanner sc = new Scanner(filePath, StandardCharsets.UTF_8)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine().trim();
                if (line.startsWith("SpertaClient:")) {
                    return line.substring("SpertaClient:".length()).trim();
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, e, () -> "Error reading attestation.txt: " + e.getMessage());
        }
        return null;
    }

    class ServerThread extends Thread {
        private final SSLSocket socket;
        private final String referenceClientPath;

        ServerThread(SSLSocket inSocket, String referenceClientPath) {
            this.socket = inSocket;
            this.referenceClientPath = referenceClientPath;
        }

       @Override
        public void run() {
            String username = null;

            try (SSLSocket clientSocket = this.socket;
                 ObjectOutputStream outStream = new ObjectOutputStream(clientSocket.getOutputStream());
                 ObjectInputStream inStream = new ObjectInputStream(clientSocket.getInputStream())) {

                // STEP 1: Binary Attestation
                if (referenceClientPath != null && !handleAttestation(inStream, outStream)) {
                    return;
                }

                // STEP 2: Authentication Loop with Retry
                while (username == null && !Thread.currentThread().isInterrupted()) {
                    String user = (String) inStream.readObject();
                    String pass = (String) inStream.readObject();
                    LOGGER.log(Level.INFO, "Received credentials for: {0}", user);

                    int authResult = storageDAO.authenticateUser(user, pass);

                    if (authResult == 0) {
                        outStream.writeObject(0); // WRONG-PWD
                        outStream.flush();
                        LOGGER.log(Level.INFO, "WRONG-PWD: {0}", user);
                    } else if (authResult == 1) {
                        outStream.writeObject(1); // OK-USER
                        outStream.flush();
                        LOGGER.log(Level.INFO, "OK-USER: {0}", user);
                        username = user;
                    } else if (authResult == 2) {
                        // Request certificate from client
                        outStream.writeObject("SEND-CERT");
                        outStream.flush();

                        byte[] certBytes = (byte[]) inStream.readObject();
                        storageDAO.registerNewUser(user, pass, certBytes);

                        LOGGER.log(Level.INFO, "OK-NEW-USER: {0}", user);
                        username = user;
                    }
                }

                // STEP 3: Message / Command Processing Loop
                receiveMessages(inStream, outStream, username);

            } catch (IOException | ClassNotFoundException exception) {
                LOGGER.log(Level.INFO, "Connection closed for client: {0}", (username != null ? username : "unauthenticated"));
            } catch (Exception e) {
                final String finalUser = username;
                LOGGER.log(Level.SEVERE, e, () -> "Unexpected exception in ServerThread for client " + finalUser + ": " + e.getMessage());
            }
        }

        private boolean handleAttestation(ObjectInputStream in, ObjectOutputStream out) throws IOException {
            long nonce = SECURE_RANDOM.nextLong();
            out.writeLong(nonce);
            out.flush();

            try {
                byte[] clientHash = (byte[]) in.readObject();

                Path refPath = Paths.get(referenceClientPath);
                if (!Files.exists(refPath)) {
                    LOGGER.log(Level.WARNING, "Reference client executable not found: {0}", referenceClientPath);
                    out.writeObject(RESP_NOK_ATTEST);
                    out.flush();
                    return false;
                }

                byte[] referenceJarBytes = Files.readAllBytes(refPath);
                byte[] serverHash = CryptoService.computeHashWithNonce(nonce, referenceJarBytes);

                if (Arrays.equals(clientHash, serverHash)) {
                    out.writeObject(RESP_OK_ATTEST);
                    out.flush();
                    LOGGER.info("Attestation OK (Nonce-based SHA-256 matched)");
                    return true;
                } else {
                    out.writeObject(RESP_NOK_ATTEST);
                    out.flush();
                    LOGGER.warning("Attestation FAILED: Hashes do not match");
                    return false;
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Attestation error: " + e.getMessage());
                try {
                    out.writeObject(RESP_NOK_ATTEST);
                    out.flush();
                } catch (Exception exception) {
                    // Intentionally suppressed during attestation failure reporting
                }
                return false;
            }
        }

        private void receiveMessages(ObjectInputStream inStream, ObjectOutputStream outStream, String username) {
            boolean active = true;
            try {
                while (active && !Thread.currentThread().isInterrupted()) {
                    Object input = inStream.readObject();
                    if (input == null) {
                        active = false;
                    } else {
                        active = processIncomingMessage((String) input, inStream, outStream, username);
                    }
                }
            } catch (IOException | ClassNotFoundException exception) { 
                LOGGER.log(Level.INFO, "Client {0} disconnected.", username);
            }
        }

        private boolean processIncomingMessage(String msg, ObjectInputStream inStream,
                                              ObjectOutputStream outStream, String username) throws IOException {
            LOGGER.log(Level.INFO, "Received from {0}: {1}", new Object[]{username, msg});

            String[] parts = msg.trim().split("\\s+");
            if (parts.length == 0 || parts[0].isEmpty()) {
                return true;
            }

            if ("EXIT".equalsIgnoreCase(parts[0]) || "QUIT".equalsIgnoreCase(parts[0])) {
                return false;
            }

            dispatchCommand(parts, inStream, outStream, username);
            return true;
        }

        private void dispatchCommand(String[] parts, ObjectInputStream inStream, 
                                     ObjectOutputStream outStream, String username) throws IOException {
            String command = parts[0].toUpperCase();

            switch (command) {
                case "CREATE":
                    processCreateCommand(parts, inStream, outStream, username);
                    break;
                case "RD":
                    processRdCommand(parts, outStream, username);
                    break;
                case "ADD":
                    processAddCommand(parts, inStream, outStream, username);
                    break;
                case "GET_KEY":
                    processGetKeyCommand(parts, outStream, username);
                    break;
                case "EC":
                    processEcCommand(parts, outStream, username);
                    break;
                case "RT":
                    processRtCommand(parts, outStream, username);
                    break;
                case "RH":
                    processRhCommand(parts, outStream, username);
                    break;
                default:
                    writeResponse(outStream, "Invalid command");
                    break;
            }
        }

        @SuppressWarnings("unchecked")
        private void processCreateCommand(String[] parts, ObjectInputStream inStream, 
                                          ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 2) {
                writeResponse(outStream, "Invalid CREATE command format.");
                return;
            }

            Map<String, byte[]> keys = new HashMap<>();
            try {
                Object receivedKeys = inStream.readObject();
                if (receivedKeys instanceof Map<?, ?> map) {
                    keys = (Map<String, byte[]>) map;
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, e, () -> "Error receiving section keys: " + e.getMessage());
            }

            writeResponse(outStream, handleCreate(parts[1], username, keys));
        }

        private void processRdCommand(String[] parts, ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 3) {
                writeResponse(outStream, "Invalid RD command format.");
                return;
            }
            writeResponse(outStream, handleRegisterDevice(parts[1], parts[2].toUpperCase(), username));
        }

        private void processAddCommand(String[] parts, ObjectInputStream inStream, 
                                       ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 4) {
                writeResponse(outStream, "Invalid ADD command format.");
                return;
            }
            handleAddPermission(parts[1], parts[2], parts[3], username, inStream, outStream);
        }

        private void processGetKeyCommand(String[] parts, ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 3) {
                writeResponse(outStream, "INVALID_FORMAT");
                return;
            }
            byte[] keyBytes = storageDAO.loadSectionKey(parts[1], parts[2].toUpperCase(), username);
            writeResponse(outStream, keyBytes != null ? keyBytes : "NO_KEY");
        }

        private void processEcCommand(String[] parts, ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 4) {
                writeResponse(outStream, "Invalid EC command format.");
                return;
            }
            writeResponse(outStream, handleExecuteCommand(parts[1], parts[2], parts[3], username));
        }

        private void processRtCommand(String[] parts, ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 2) {
                writeResponse(outStream, RESP_NOK);
                return;
            }
            handleRT(parts[1], username, outStream);
        }

        private void processRhCommand(String[] parts, ObjectOutputStream outStream, String username) throws IOException {
            if (parts.length < 3) {
                writeResponse(outStream, RESP_NOK);
                return;
            }
            handleRH(parts[1], parts[2], username, outStream);
        }

        private void writeResponse(ObjectOutputStream outStream, Object response) throws IOException {
            outStream.writeObject(response);
            outStream.flush();
        }

        private String handleCreate(String houseName, String owner, Map<String, byte[]> sectionKeys) {
            if (storageDAO.houseExists(houseName)) {
                return RESP_NOK;
            }

            try {
                House house = new House(houseName, owner);
                storageDAO.saveHouse(house);

                if (sectionKeys != null) {
                    for (Map.Entry<String, byte[]> entry : sectionKeys.entrySet()) {
                        storageDAO.saveSectionKey(houseName, entry.getKey(), owner, entry.getValue());
                    }
                }

                LOGGER.log(Level.INFO, "House {0} created securely for owner {1}", new Object[]{houseName, owner});
                return RESP_OK;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error creating house: " + e.getMessage());
                return RESP_NOK;
            }
        }

        private String handleRegisterDevice(String houseName, String sectionName, String requestingUser) {
            try {
                House house = storageDAO.loadHouse(houseName);
                if (house == null) {
                    return RESP_NO_HM;
                }

                if (!house.getOwner().equals(requestingUser)) {
                    return RESP_NO_PERM;
                }

                House.Section section = house.getSection(sectionName);
                if (section == null) {
                    return "Section " + sectionName + " not found.";
                }

                int nextId = section.getNextDeviceId();
                String newDeviceId = sectionName + nextId;
                section.setDeviceValue(newDeviceId, "0");

                storageDAO.saveHouse(house);
                LOGGER.log(Level.INFO, "Registered device {0} in {1}", new Object[]{newDeviceId, houseName});
                return RESP_OK;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error registering device: " + e.getMessage());
                return "Error registering device.";
            }
        }

        @SuppressWarnings("unchecked")
        private void handleAddPermission(String targetUser, String houseName, String sectionArg, String requestingUser,
                                         ObjectInputStream inStream, ObjectOutputStream outStream) throws IOException {
            try {
                House house = storageDAO.loadHouse(houseName);
                if (house == null) {
                    outStream.writeObject(RESP_NO_HM);
                    outStream.flush();
                    return;
                }

                if (!house.getOwner().equals(requestingUser)) {
                    outStream.writeObject(RESP_NO_PERM);
                    outStream.flush();
                    return;
                }

                if (!storageDAO.userExists(targetUser)) {
                    outStream.writeObject(RESP_NO_USER);
                    outStream.flush();
                    return;
                }

                boolean isAll = sectionArg.equalsIgnoreCase("all");
                String[] targetSections = isAll ? new String[]{"E", "G", "L", "M", "P", "S"} : new String[]{sectionArg.toUpperCase()};

                for (String secKey : targetSections) {
                    House.Section sec = house.getSection(secKey);
                    if (sec != null) {
                        sec.addUser(targetUser);
                    }
                }

                storageDAO.saveHouse(house);

                // E2E Key Re-wrapping step
                byte[] targetCertBytes = storageDAO.getUserCertificate(targetUser);
                Map<String, byte[]> keysToWrap = new HashMap<>();

                for (String secKey : targetSections) {
                    byte[] k = storageDAO.loadSectionKey(houseName, secKey, requestingUser);
                    if (k != null) {
                        keysToWrap.put(secKey, k);
                    }
                }

                outStream.writeObject(new Object[]{"E2E_ADD", keysToWrap, targetCertBytes});
                outStream.flush();

                Object resp = inStream.readObject();
                if (resp instanceof Map<?, ?> rawMap) {
                    Map<String, byte[]> newKeys = (Map<String, byte[]>) rawMap;
                    for (Map.Entry<String, byte[]> entry : newKeys.entrySet()) {
                        storageDAO.saveSectionKey(houseName, entry.getKey(), targetUser, entry.getValue());
                    }
                    outStream.writeObject("OK - Target user " + targetUser + " now has section key(s).");
                } else {
                    outStream.writeObject("NOK - Failed to receive re-wrapped keys (E2E).");
                }
                outStream.flush();

            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error in handleAddPermission: " + e.getMessage());
                outStream.writeObject("NOK - Internal error in ADD.");
                outStream.flush();
            }
        }

        private String handleExecuteCommand(String houseName, String deviceId, String valueStr, String requestingUser) {
            if (valueStr == null || valueStr.trim().isEmpty()) {
                return RESP_NOK;
            }

            try {
                House house = storageDAO.loadHouse(houseName);
                if (house == null) {
                    return RESP_NO_HM;
                }

                String sectionName = String.valueOf(deviceId.charAt(0)).toUpperCase();
                if (!house.isAuthorized(requestingUser, sectionName)) {
                    return RESP_NO_PERM;
                }

                House.Section section = house.getSection(sectionName);
                if (section == null || !section.getDevices().containsKey(deviceId)) {
                    return RESP_NO_D;
                }

                section.setDeviceValue(deviceId, valueStr);
                storageDAO.saveHouse(house);
                storageDAO.appendDeviceLog(houseName, deviceId, valueStr);

                return RESP_OK;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error in executeCommand: " + e.getMessage());
                return "Error securely updating device state.";
            }
        }

        private void handleRT(String houseName, String username, ObjectOutputStream outStream) throws IOException {
            try {
                House house = storageDAO.loadHouse(houseName);
                if (house == null) {
                    outStream.writeObject(RESP_NO_HM);
                    outStream.flush();
                    return;
                }

                StringBuilder content = new StringBuilder();
                List<String> accessibleSections = new ArrayList<>();

                for (Map.Entry<String, House.Section> entry : house.getSections().entrySet()) {
                    String secName = entry.getKey();
                    House.Section sec = entry.getValue();

                    if (house.isAuthorized(username, secName)) {
                        accessibleSections.add(secName);
                        for (Map.Entry<String, String> dev : sec.getDevices().entrySet()) {
                            content.append(dev.getKey()).append(":").append(dev.getValue()).append("\n");
                        }
                    }
                }

                if (accessibleSections.isEmpty()) {
                    outStream.writeObject(RESP_NO_PERM);
                    outStream.flush();
                    return;
                }

                if (content.isEmpty()) {
                    outStream.writeObject(RESP_NO_DATA);
                    outStream.flush();
                    return;
                }

                Map<String, byte[]> keysMap = new HashMap<>();
                for (String sec : accessibleSections) {
                    byte[] k = storageDAO.loadSectionKey(houseName, sec, username);
                    if (k != null) {
                        keysMap.put(sec, k);
                    }
                }

                byte[] data = content.toString().getBytes(StandardCharsets.UTF_8);
                outStream.writeObject(new Object[]{RESP_OK, keysMap});
                outStream.writeObject((long) data.length);
                outStream.write(data);
                outStream.flush();

            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error in handleRT: " + e.getMessage());
                outStream.writeObject(RESP_NOK);
                outStream.flush();
            }
        }

        private void handleRH(String houseName, String deviceId, String username, ObjectOutputStream outStream) throws IOException {
            try {
                House house = storageDAO.loadHouse(houseName);
                if (house == null) {
                    outStream.writeObject(RESP_NO_HM);
                    outStream.flush();
                    return;
                }

                String sectionName = String.valueOf(deviceId.charAt(0)).toUpperCase();
                House.Section sec = house.getSection(sectionName);
                if (sec == null || !sec.getDevices().containsKey(deviceId)) {
                    outStream.writeObject(RESP_NO_D);
                    outStream.flush();
                    return;
                }

                if (!house.isAuthorized(username, sectionName)) {
                    outStream.writeObject(RESP_NO_PERM);
                    outStream.flush();
                    return;
                }

                byte[] data = storageDAO.loadDeviceLog(houseName, deviceId);
                if (data == null || data.length == 0) {
                    outStream.writeObject(RESP_NO_DATA);
                    outStream.flush();
                    return;
                }

                Map<String, byte[]> keysMap = new HashMap<>();
                byte[] k = storageDAO.loadSectionKey(houseName, sectionName, username);
                if (k != null) {
                    keysMap.put(sectionName, k);
                }

                outStream.writeObject(new Object[]{RESP_OK, keysMap});
                outStream.writeObject((long) data.length);
                outStream.write(data);
                outStream.flush();

            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, e, () -> "Error in handleRH: " + e.getMessage());
                outStream.writeObject(RESP_NOK);
                outStream.flush();
            }
        }
    }
}