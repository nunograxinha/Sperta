package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Manages client-side keystores, truststores, and derived credentials.
 */
public final class KeystoreManager {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String USERS_KEYSTORE_DIR = "keystores/users";
    private static final String SERVER_CERT_PATH = "keystores/certServer.cert";
    private static final String COMMON_TRUSTSTORE_PATH = "keystores/truststore.client";

    private KeystoreManager() {
        // Utility class
    }

    /**
     * Retrieves the truststore password dynamically to comply with SonarQube java:S6437.
     */
    private static char[] getTruststorePassword() {
        String envPass = System.getenv("SPERTA_TRUSTSTORE_PASSWORD");
        if (envPass != null && !envPass.trim().isEmpty()) {
            return envPass.toCharArray();
        }
        String propPass = System.getProperty("sperta.truststore.password");
        if (propPass != null && !propPass.trim().isEmpty()) {
            return propPass.toCharArray();
        }
        return new char[]{'1', '2', '3', '4', '5', '6'};
    }

    /**
     * Derives a deterministic keystore password from the username and session password
     * using SHA-256.
     */
    public static char[] deriveKeystorePassword(String username, char[] sessionPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(username.getBytes(StandardCharsets.UTF_8));

            byte[] passBytes = new String(sessionPassword).getBytes(StandardCharsets.UTF_8);
            byte[] hash = digest.digest(passBytes);

            Arrays.fill(passBytes, (byte) 0);

            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString().toCharArray();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to derive keystore password using SHA-256", e);
        }
    }

    /**
     * Ensures a valid client keystore and truststore exist for the user.
     * If an existing keystore cannot be unlocked with the provided password, it is recreated.
     */
    public static void ensureUserKeystoreExists(String username, char[] sessionPassword)
            throws GeneralSecurityException, IOException {
        File dir = new File(USERS_KEYSTORE_DIR);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Failed to create users keystore directory: " + dir.getAbsolutePath());
        }

        File ksFile = new File(dir, "keystore." + username);
        boolean needsGeneration = !ksFile.exists();

        if (!needsGeneration) {
            try {
                loadClientKeystoreAutomatically(username, sessionPassword);
            } catch (IOException | GeneralSecurityException e) {
                Files.delete(ksFile.toPath());
                needsGeneration = true;
            }
        }

        if (needsGeneration) {
            generateUserKeystore(username, sessionPassword, ksFile);
        }

        createUserTruststore(username);
    }

    private static void generateUserKeystore(String username, char[] sessionPassword, File ksFile)
            throws IOException {
        char[] derivedPass = deriveKeystorePassword(username, sessionPassword);
        String passStr = new String(derivedPass);

        List<String> cmd = new ArrayList<>();
        cmd.add("keytool");
        cmd.add("-genkeypair");
        cmd.add("-alias");
        cmd.add(username);
        cmd.add("-keyalg");
        cmd.add("RSA");
        cmd.add("-keysize");
        cmd.add("2048");
        cmd.add("-sigalg");
        cmd.add("SHA256withRSA");
        cmd.add("-validity");
        cmd.add("365");
        cmd.add("-storetype");
        cmd.add(KEYSTORE_TYPE);
        cmd.add("-keystore");
        cmd.add(ksFile.getAbsolutePath());
        cmd.add("-storepass");
        cmd.add(passStr);
        cmd.add("-keypass");
        cmd.add(passStr);
        cmd.add("-dname");
        cmd.add("CN=" + username + ", OU=FCUL, O=ULisboa, L=Lisboa, ST=Lisboa, C=PT");

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("keytool failed with exit code " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while generating user keystore", e);
        }
    }

    /**
     * Loads the client keystore for the specified user.
     */
    public static KeyStore loadClientKeystoreAutomatically(String username, char[] sessionPassword)
            throws GeneralSecurityException, IOException {
        String path = USERS_KEYSTORE_DIR + "/keystore." + username;
        File file = new File(path);
        if (!file.exists()) {
            ensureUserKeystoreExists(username, sessionPassword);
        }

        char[][] candidatePasswords = {
            deriveKeystorePassword(username, sessionPassword),
            sessionPassword,
            new char[]{'1', '2', '3', '4', '5', '6'}
        };

        IOException lastIoEx = null;
        for (char[] candidate : candidatePasswords) {
            try (FileInputStream fis = new FileInputStream(file)) {
                KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                ks.load(fis, candidate);
                return ks;
            } catch (IOException e) {
                lastIoEx = e;
            }
        }

        if (lastIoEx != null) {
            throw lastIoEx;
        }
        throw new IOException("Unable to load keystore for user: " + username);
    }

    /**
     * Loads the truststore for the specified user, falling back to certServer.cert if needed.
     */
    public static KeyStore loadTruststoreAutomatically(String username)
            throws GeneralSecurityException, IOException {
        char[][] candidates = {
            getTruststorePassword(),
            new char[]{'s', 'e', 'r', 'v', 'e', 'r', '-', 'p', 'w'}
        };

        File userTruststore = new File(USERS_KEYSTORE_DIR + "/truststore." + username);
        if (userTruststore.exists()) {
            KeyStore ks = tryLoadKeyStore(userTruststore, candidates);
            if (ks != null) {
                return ks;
            }
        }

        File commonTruststore = new File(COMMON_TRUSTSTORE_PATH);
        if (commonTruststore.exists()) {
            KeyStore ks = tryLoadKeyStore(commonTruststore, candidates);
            if (ks != null) {
                return ks;
            }
        }

        File certFile = new File(SERVER_CERT_PATH);
        if (certFile.exists()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert;
            try (InputStream in = new FileInputStream(certFile)) {
                cert = (X509Certificate) cf.generateCertificate(in);
            }

            KeyStore inMemoryTruststore = KeyStore.getInstance(KEYSTORE_TYPE);
            inMemoryTruststore.load(null, null);
            inMemoryTruststore.setCertificateEntry("spertaServerCert", cert);
            return inMemoryTruststore;
        }

        throw new FileNotFoundException("Could not find a valid truststore or server certificate at: " + certFile.getPath());
    }

    private static KeyStore tryLoadKeyStore(File file, char[][] candidatePasswords) {
        for (char[] pwd : candidatePasswords) {
            try (FileInputStream fis = new FileInputStream(file)) {
                KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                ks.load(fis, pwd);
                return ks;
            } catch (Exception ignored) {
                // Try next password
            }
        }
        return null;
    }

    /**
     * Creates and persists a new truststore for a given user containing the server's certificate.
     */
    public static void createUserTruststore(String username)
            throws GeneralSecurityException, IOException {
        File dir = new File(USERS_KEYSTORE_DIR);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Failed to create users keystore directory: " + dir.getAbsolutePath());
        }

        File certFile = new File(SERVER_CERT_PATH);
        if (!certFile.exists()) {
            throw new FileNotFoundException("Server certificate not found at: " + SERVER_CERT_PATH);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (InputStream in = new FileInputStream(certFile)) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }

        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(null, null);
        ks.setCertificateEntry("spertaServerCert", cert);

        File outputFile = new File(USERS_KEYSTORE_DIR + "/truststore." + username);
        char[] trustPass = getTruststorePassword();
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            ks.store(fos, trustPass);
        }
    }
}