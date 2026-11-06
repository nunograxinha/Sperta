package server;

import utils.CryptoService;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data Access Object managing persistent storage, concurrency, and integrity checks.
 * Encapsulates PBE encryption-at-rest for house profiles/logs and plaintext salted credentials.
 */
public class StorageDAO {

    private static final Logger LOGGER = Logger.getLogger(StorageDAO.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String DATA_DIR = "data";
    private static final String HOMES_DIR = "data/homes";
    private static final String LOGS_DIR = "RH";
    private static final String KEYS_DIR = "data/keys";
    private static final String CERTS_DIR = "data/certs";
    private static final String USERS_FILE = "data/users.txt";
    private static final String SALT_FILE = "data/server_salt.bin";
    private static final String CERTIFICATE_SUFFIX = ".cert";
    private static final String HISTORY_SUFFIX = "_history.csv";

    private static final DateTimeFormatter LOG_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ZoneId DEFAULT_ZONE_ID = ZoneId.systemDefault();

    private final ConcurrentHashMap<String, ReentrantReadWriteLock> fileLocks = new ConcurrentHashMap<>();
    private final String cipherPassword;
    private byte[] pbeSalt;

    public StorageDAO(String cipherPassword) throws IOException, GeneralSecurityException {
        this.cipherPassword = cipherPassword;
        ensureDirectories();
        initPbeSalt();
        initUsersFile();
    }

    private void ensureDirectories() throws IOException {
        Files.createDirectories(Paths.get(DATA_DIR));
        Files.createDirectories(Paths.get(HOMES_DIR));
        Files.createDirectories(Paths.get(LOGS_DIR));
        Files.createDirectories(Paths.get(KEYS_DIR));
        Files.createDirectories(Paths.get(CERTS_DIR));
    }

    private void initPbeSalt() throws IOException {
        Path saltPath = Paths.get(SALT_FILE);
        if (Files.exists(saltPath)) {
            this.pbeSalt = Files.readAllBytes(saltPath);
        } else {
            this.pbeSalt = CryptoService.generateRandomSalt();
            Files.write(saltPath, this.pbeSalt);
        }
    }

    private void initUsersFile() throws IOException, GeneralSecurityException {
        Path usersPath = Paths.get(USERS_FILE);
        if (!Files.exists(usersPath)) {
            Files.createFile(usersPath);
            updateFileHash(USERS_FILE);
        }
    }

    private ReentrantReadWriteLock getLock(String path) {
        return fileLocks.computeIfAbsent(path, k -> new ReentrantReadWriteLock());
    }

    // ==========================================
    // 1. User Management (Plaintext with Salted Hashes)
    // ==========================================

    public synchronized boolean userExists(String username) {
        File usersFile = new File(USERS_FILE);
        if (!usersFile.exists()) {
            usersFile = new File("users.txt");
        }
        if (!usersFile.exists()) {
            return false;
        }

        try (Scanner scanner = new Scanner(usersFile, StandardCharsets.UTF_8)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().trim();
                if (line.startsWith(username + ":")) {
                    return true;
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error reading users file: {0}", e.getMessage());
        }
        return false;
}

    public int authenticateUser(String username, String password) throws IOException, GeneralSecurityException {
        Lock lock = getLock(USERS_FILE).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(USERS_FILE)) {
                throw new SecurityException("NOK-INTEGRITY: users.txt integrity failure.");
            }
            try (Scanner sc = new Scanner(new File(USERS_FILE), StandardCharsets.UTF_8.name())) {
                while (sc.hasNextLine()) {
                    String line = sc.nextLine().trim();
                    if (line.isEmpty()) {
                        continue;
                    }

                    String[] parts = line.split(":");
                    if (parts.length == 3 && parts[0].equals(username)) {
                        String storedHash = parts[1];
                        String storedSalt = parts[2];
                        String calculatedHash = hashPassword(password, storedSalt);
                        return storedHash.equals(calculatedHash) ? 1 : 0; // 1 = OK-USER, 0 = WRONG-PWD
                    }
                }
            }
            return 2; // 2 = OK-NEW-USER
        } finally {
            lock.unlock();
        }
    }

    public synchronized boolean registerNewUser(String username, String password, byte[] certBytes) {
        File usersFile = new File(USERS_FILE);
        if (!usersFile.exists()) {
            usersFile = new File("users.txt");
        }

        try {
            // 1. Generate 16-byte random salt
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            // 2. Hash password with salt using SHA-256 (matches username:hash:salt)
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String hashBase64 = Base64.getEncoder().encodeToString(hashed);

            // 3. Save certificate file if certBytes were provided
            if (certBytes != null && certBytes.length > 0) {
                File certsDir = new File(CERTS_DIR);
                if (!certsDir.exists()) {
                    certsDir = new File("keystores/users");
                }
                if (!certsDir.exists()) {
                    certsDir.mkdirs();
                }

                File certFile = new File(certsDir, username + CERTIFICATE_SUFFIX);
                try (FileOutputStream fos = new FileOutputStream(certFile)) {
                    fos.write(certBytes);
                }
            }

            // 4. Append username:hash:salt to users file
            if (usersFile.length() > 0) {
                try (RandomAccessFile file = new RandomAccessFile(usersFile, "r")) {
                    file.seek(usersFile.length() - 1);
                    byte lastByte = file.readByte();
                    if (lastByte != '\n' && lastByte != '\r') {
                        try (FileWriter separator = new FileWriter(usersFile, true)) {
                            separator.write(System.lineSeparator());
                        }
                    }
                }
            }
            try (FileWriter fw = new FileWriter(usersFile, true);
                PrintWriter pw = new PrintWriter(fw)) {
                pw.println(username + ":" + hashBase64 + ":" + saltBase64);
            }
            updateFileHash(usersFile.getPath());
            return true;
        } catch (GeneralSecurityException | IOException e) {
            LOGGER.log(Level.WARNING, "Failed to register new user: {0}", e.getMessage());
            return false;
        }
    }

    public byte[] getUserCertificate(String username) throws IOException {
        Path certPath = Paths.get(CERTS_DIR, username + CERTIFICATE_SUFFIX);
        return Files.exists(certPath) ? Files.readAllBytes(certPath) : null;
    }

    public synchronized void saveUserCertificate(String username, byte[] certBytes) throws IOException {
        if (certBytes == null || certBytes.length == 0) {
            throw new IOException("User certificate is empty");
        }

        Files.createDirectories(Paths.get(CERTS_DIR));
        Files.write(
                Paths.get(CERTS_DIR, username + CERTIFICATE_SUFFIX),
                certBytes,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );
    }

    // ==========================================
    // 2. House Management (PBE Encrypted at Rest)
    // ==========================================

    public boolean houseExists(String houseName) {
        return Files.exists(Paths.get(HOMES_DIR, houseName + ".txt"));
    }

    public House loadHouse(String houseName) throws IOException, GeneralSecurityException {
        Path filePath = Paths.get(HOMES_DIR, houseName + ".txt");
        String path = filePath.toString();
        if (!Files.exists(filePath)) {
            return null;
        }

        Lock lock = getLock(path).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(path)) {
                throw new SecurityException("NOK-INTEGRITY: House file " + houseName + " integrity failure.");
            }
            byte[] encrypted = Files.readAllBytes(filePath);
            byte[] decrypted = CryptoService.decryptPBE(encrypted, cipherPassword, pbeSalt);
            String content = new String(decrypted, StandardCharsets.UTF_8);
            return House.fromFileFormat(houseName, content);
        } finally {
            lock.unlock();
        }
    }

    public void saveHouse(House house) throws IOException, GeneralSecurityException {
        Path filePath = Paths.get(HOMES_DIR, house.getName() + ".txt");
        String path = filePath.toString();
        Lock lock = getLock(path).writeLock();
        lock.lock();
        try {
            byte[] plainBytes = house.toFileFormat().getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = CryptoService.encryptPBE(plainBytes, cipherPassword, pbeSalt);
            Files.write(Paths.get(path), encryptedBytes);
            updateFileHash(path);
        } finally {
            lock.unlock();
        }
    }

    // ==========================================
    // 3. Device Logs and E2E Key Storage
    // ==========================================

    public synchronized void logDeviceEvent(String houseName, String deviceId, int value, String timestamp) {
        File logDir = new File(LOGS_DIR);
        if (!logDir.exists()) {
            logDir.mkdirs();
        }

        File csvFile = new File(logDir, houseName + "_" + deviceId + HISTORY_SUFFIX);
        boolean isNew = !csvFile.exists() || csvFile.length() == 0;

        // 1. Append the new row to the CSV file
        try (FileWriter fw = new FileWriter(csvFile, true);
            PrintWriter pw = new PrintWriter(fw)) {
            if (isNew) {
                pw.println("device,value,timestamp");
            }
            pw.println(deviceId + "," + value + "," + timestamp);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to write device log: {0}", e.getMessage());
        }

        // 2. Update the .hash integrity file if your StorageDAO maintains log hashes
    }
    public void appendDeviceLog(String houseName, String deviceId, String valueStr) 
            throws IOException {
        Path logDirPath = Paths.get(LOGS_DIR);
        Files.createDirectories(logDirPath);

        String path = logDirPath.resolve(houseName + "_" + deviceId + HISTORY_SUFFIX).toString();
        Lock lock = getLock(path).writeLock();
        lock.lock();
        try {
            StringBuilder sb = new StringBuilder();
            Path logFilePath = Paths.get(path);
            if (Files.exists(logFilePath) && Files.size(logFilePath) > 0) {
                sb.append(Files.readString(logFilePath, StandardCharsets.UTF_8));
            } else {
                sb.append("device,value,timestamp\n");
            }

            String timestamp = LocalDateTime.now(DEFAULT_ZONE_ID).format(LOG_DATE_FORMATTER);
            sb.append(deviceId).append(",").append(valueStr).append(",").append(timestamp).append("\n");

            Files.writeString(logFilePath, sb.toString(), StandardCharsets.UTF_8);
        } finally {
            lock.unlock();
        }
    }

    public byte[] loadDeviceLog(String houseName, String deviceId) throws IOException {
        Path logFilePath = Paths.get(
                LOGS_DIR,
                houseName + "_" + deviceId + HISTORY_SUFFIX);
        if (!Files.exists(logFilePath)) {
            return new byte[0]; // ou null se a lógica de quem chama depender explicitamente de null
        }

        Lock lock = getLock(logFilePath.toString()).readLock();
        lock.lock();
        try {
            return Files.readAllBytes(logFilePath);
        } finally {
            lock.unlock();
        }
    }

    public void saveSectionKey(String houseName, String section, String user, byte[] keyBytes) throws IOException {
        String path = KEYS_DIR + "/key." + houseName + "." + section.toUpperCase() + "." + user;
        Files.write(Paths.get(path), keyBytes);
    }

    public byte[] loadSectionKey(String houseName, String section, String user) throws IOException {
        Path keyPath = Paths.get(KEYS_DIR, "key." + houseName + "." + section.toUpperCase() + "." + user);
        return Files.exists(keyPath) ? Files.readAllBytes(keyPath) : null;
    }

    // ==========================================
    // 4. SHA-256 Digest and Integrity Helpers
    // ==========================================

    private String hashPassword(String password, String saltBase64) throws GeneralSecurityException {
        byte[] salt = Base64.getDecoder().decode(saltBase64);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[salt.length + passwordBytes.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(passwordBytes, 0, combined, salt.length, passwordBytes.length);
        byte[] digest = CryptoService.computeSHA256(combined);
        return Base64.getEncoder().encodeToString(digest);
    }

    private void updateFileHash(String filePath) throws IOException, GeneralSecurityException {
        byte[] content = Files.readAllBytes(Paths.get(filePath));
        byte[] hash = CryptoService.computeSHA256(content);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);
        Files.write(Paths.get(filePath + ".hash"), hashBase64.getBytes(StandardCharsets.UTF_8));
    }

    private boolean verifyFileHash(String filePath) {
        Path hashPath = Paths.get(filePath + ".hash");
        if (!Files.exists(hashPath)) {
            return true;
        }
        try {
            String stored = new String(Files.readAllBytes(hashPath), StandardCharsets.UTF_8).trim();
            byte[] content = Files.readAllBytes(Paths.get(filePath));
            String calculated = Base64.getEncoder().encodeToString(CryptoService.computeSHA256(content));
            return stored.equals(calculated);
        } catch (IOException | GeneralSecurityException e) {
            return false;
        }
    }
}