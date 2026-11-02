package server;

import utils.CryptoService;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Data Access Object managing storage, concurrency, and integrity checks.
 * Encapsulates PBE encryption-at-rest for house/log files and plaintext storage with salts for user credentials.
 */
public class StorageDAO {

    private static final String DATA_DIR = "data";
    private static final String HOMES_DIR = "data/homes";
    private static final String LOGS_DIR = "data/logs";
    private static final String KEYS_DIR = "data/keys";
    private static final String CERTS_DIR = "data/certs";
    private static final String USERS_FILE = "data/users.txt";
    private static final String SALT_FILE = "data/server_salt.bin";

    private final ConcurrentHashMap<String, ReentrantReadWriteLock> fileLocks = new ConcurrentHashMap<>();
    private final String cipherPassword;
    private byte[] pbeSalt;

    public StorageDAO(String cipherPassword) throws Exception {
        this.cipherPassword = cipherPassword;
        ensureDirectories();
        initPbeSalt();
        initUsersFile();
    }

    private void ensureDirectories() {
        new File(HOMES_DIR).mkdirs();
        new File(LOGS_DIR).mkdirs();
        new File(KEYS_DIR).mkdirs();
        new File(CERTS_DIR).mkdirs();
    }

    private void initPbeSalt() throws Exception {
        File saltFile = new File(SALT_FILE);
        if (saltFile.exists()) {
            this.pbeSalt = Files.readAllBytes(saltFile.toPath());
        } else {
            this.pbeSalt = CryptoService.generateRandomSalt();
            Files.write(saltFile.toPath(), this.pbeSalt);
        }
    }

    private void initUsersFile() throws Exception {
        File users = new File(USERS_FILE);
        if (!users.exists()) {
            users.createNewFile();
            updateFileHash(USERS_FILE);
        }
    }

    private ReentrantReadWriteLock getLock(String path) {
        return fileLocks.computeIfAbsent(path, k -> new ReentrantReadWriteLock());
    }

    // ==========================================
    // 1. User Management (Plaintext with Salted Hashes)
    // ==========================================

    public boolean userExists(String username) {
        Lock lock = getLock(USERS_FILE).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(USERS_FILE)) {
                throw new SecurityException("NOK-INTEGRITY: Users file integrity check failed.");
            }
            try (Scanner sc = new Scanner(new File(USERS_FILE), StandardCharsets.UTF_8.name())) {
                while (sc.hasNextLine()) {
                    String line = sc.nextLine().trim();
                    if (!line.isEmpty()) {
                        String[] parts = line.split(":");
                        if (parts.length >= 1 && parts[0].equals(username)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        } finally {
            lock.unlock();
        }
    }

    public int authenticateUser(String username, String password) throws Exception {
        Lock lock = getLock(USERS_FILE).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(USERS_FILE)) {
                throw new SecurityException("NOK-INTEGRITY: users.txt integrity failure.");
            }
            try (Scanner sc = new Scanner(new File(USERS_FILE), StandardCharsets.UTF_8.name())) {
                while (sc.hasNextLine()) {
                    String line = sc.nextLine().trim();
                    if (line.isEmpty()) continue;

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

    public void registerNewUser(String username, String password, byte[] certificateBytes) throws Exception {
        Lock lock = getLock(USERS_FILE).writeLock();
        lock.lock();
        try {
            byte[] saltBytes = CryptoService.generateRandomSalt();
            String saltBase64 = Base64.getEncoder().encodeToString(saltBytes);
            String hashBase64 = hashPassword(password, saltBase64);

            String line = username + ":" + hashBase64 + ":" + saltBase64 + System.lineSeparator();
            Files.write(Paths.get(USERS_FILE), line.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
            updateFileHash(USERS_FILE);

            if (certificateBytes != null && certificateBytes.length > 0) {
                Files.write(Paths.get(CERTS_DIR, username + ".cert"), certificateBytes);
            }
        } finally {
            lock.unlock();
        }
    }

    public byte[] getUserCertificate(String username) throws IOException {
        File cert = new File(CERTS_DIR, username + ".cert");
        return cert.exists() ? Files.readAllBytes(cert.toPath()) : null;
    }

    // ==========================================
    // 2. House Management (PBE Encrypted at Rest)
    // ==========================================

    public boolean houseExists(String houseName) {
        return new File(HOMES_DIR, houseName + ".txt").exists();
    }

    public House loadHouse(String houseName) throws Exception {
        String path = HOMES_DIR + "/" + houseName + ".txt";
        File f = new File(path);
        if (!f.exists()) return null;

        Lock lock = getLock(path).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(path)) {
                throw new SecurityException("NOK-INTEGRITY: House file " + houseName + " integrity failure.");
            }
            byte[] encrypted = Files.readAllBytes(f.toPath());
            byte[] decrypted = CryptoService.decryptPBE(encrypted, cipherPassword, pbeSalt);
            String content = new String(decrypted, StandardCharsets.UTF_8);
            return House.fromFileFormat(houseName, content);
        } finally {
            lock.unlock();
        }
    }

    public void saveHouse(House house) throws Exception {
        String path = HOMES_DIR + "/" + house.getName() + ".txt";
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

    public void appendDeviceLog(String houseName, String deviceId, String valueStr) throws Exception {
        String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
        File logDir = new File(LOGS_DIR + "/" + houseName + "/" + section);
        logDir.mkdirs();

        String path = logDir.getPath() + "/" + deviceId + ".csv";
        Lock lock = getLock(path).writeLock();
        lock.lock();
        try {
            StringBuilder sb = new StringBuilder();
            File logFile = new File(path);
            if (logFile.exists() && logFile.length() > 0) {
                if (!verifyFileHash(path)) {
                    throw new SecurityException("NOK-INTEGRITY: Log file corrupted: " + path);
                }
                byte[] dec = CryptoService.decryptPBE(Files.readAllBytes(logFile.toPath()), cipherPassword, pbeSalt);
                sb.append(new String(dec, StandardCharsets.UTF_8));
            } else {
                sb.append("device,value,timestamp\n");
            }

            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            sb.append(deviceId).append(",").append(valueStr).append(",").append(timestamp).append("\n");

            byte[] enc = CryptoService.encryptPBE(sb.toString().getBytes(StandardCharsets.UTF_8), cipherPassword, pbeSalt);
            Files.write(Paths.get(path), enc);
            updateFileHash(path);
        } finally {
            lock.unlock();
        }
    }

    public byte[] loadDeviceLog(String houseName, String deviceId) throws Exception {
        String section = String.valueOf(deviceId.charAt(0)).toUpperCase();
        String path = LOGS_DIR + "/" + houseName + "/" + section + "/" + deviceId + ".csv";
        File logFile = new File(path);
        if (!logFile.exists()) return null;

        Lock lock = getLock(path).readLock();
        lock.lock();
        try {
            if (!verifyFileHash(path)) {
                throw new SecurityException("NOK-INTEGRITY: Log integrity failure: " + path);
            }
            return CryptoService.decryptPBE(Files.readAllBytes(logFile.toPath()), cipherPassword, pbeSalt);
        } finally {
            lock.unlock();
        }
    }

    public void saveSectionKey(String houseName, String section, String user, byte[] keyBytes) throws IOException {
        String path = KEYS_DIR + "/key." + houseName + "." + section.toUpperCase() + "." + user;
        Files.write(Paths.get(path), keyBytes);
    }

    public byte[] loadSectionKey(String houseName, String section, String user) throws IOException {
        File kf = new File(KEYS_DIR + "/key." + houseName + "." + section.toUpperCase() + "." + user);
        return kf.exists() ? Files.readAllBytes(kf.toPath()) : null;
    }

    // ==========================================
    // 4. SHA-256 Digest and Integrity Helpers
    // ==========================================

    private String hashPassword(String password, String saltBase64) throws Exception {
        String combined = password + saltBase64;
        byte[] digest = CryptoService.computeSHA256(combined.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(digest);
    }

    private void updateFileHash(String filePath) throws Exception {
        byte[] content = Files.readAllBytes(Paths.get(filePath));
        byte[] hash = CryptoService.computeSHA256(content);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);
        Files.write(Paths.get(filePath + ".hash"), hashBase64.getBytes(StandardCharsets.UTF_8));
    }

    private boolean verifyFileHash(String filePath) {
        File hashFile = new File(filePath + ".hash");
        if (!hashFile.exists()) return true;
        try {
            String stored = new String(Files.readAllBytes(hashFile.toPath()), StandardCharsets.UTF_8).trim();
            byte[] content = Files.readAllBytes(Paths.get(filePath));
            String calculated = Base64.getEncoder().encodeToString(CryptoService.computeSHA256(content));
            return stored.equals(calculated);
        } catch (Exception e) {
            return false;
        }
    }
}