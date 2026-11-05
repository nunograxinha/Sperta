package client;

import utils.CryptoService;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public final class ClientCryptoHelper {

    private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";
    private static final String CERT_TYPE_X509 = "X.509";
    private static final String KEYSTORE_DIR = "keystores";
    private static final String USERS_SUBDIR = "users";

    private ClientCryptoHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Used by SpertaClient.java
     */
    public static byte[] loadUserCertificateBytes(String keystorePath, String keystorePassword, String alias) {
        try {
            return extractUserCertificate(keystorePath, keystorePassword, alias);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to load user certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Used by SpertaNetworkService.java (GUI)
     */
    public static byte[] extractUserCertificate(String keystorePath, String keystorePassword, String alias) 
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
        try (InputStream in = new FileInputStream(keystorePath)) {
            keyStore.load(in, keystorePassword.toCharArray());
        }

        Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            Enumeration<String> aliases = keyStore.aliases();
            if (aliases.hasMoreElements()) {
                cert = keyStore.getCertificate(aliases.nextElement());
            }
        }

        if (cert == null) {
            throw new IllegalArgumentException("Certificate not found in keystore: " + keystorePath);
        }

        return cert.getEncoded();
    }

    /**
     * Saves the received X.509 certificate into the local user truststore.
     */
    public static void saveCertificateToTrustStore(String trustStorePath, String trustStorePass,
                                                  String alias, byte[] certBytes) 
            throws GeneralSecurityException, IOException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        File tsFile = new File(trustStorePath);

        char[] passChars = (trustStorePass != null && !trustStorePass.isEmpty()) 
                ? trustStorePass.toCharArray() 
                : null;

        if (tsFile.exists()) {
            try (InputStream in = new FileInputStream(tsFile)) {
                trustStore.load(in, passChars);
            }
        } else {
            trustStore.load(null, passChars);
        }

        CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE_X509);
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
        trustStore.setCertificateEntry(alias, cert);

        try (OutputStream out = new FileOutputStream(tsFile)) {
            trustStore.store(out, (passChars != null) ? passChars : "".toCharArray());
        }
    }

    /**
     * Unwraps section keys using the user's private key and re-wraps them with the target user's public key.
     */
    public static Map<String, byte[]> rewrapSectionKeys(Map<String, byte[]> currentWrappedKeys,
                                                        byte[] targetCertBytes,
                                                        String keystorePath,
                                                        String keystorePass,
                                                        String requestingUser) 
            throws GeneralSecurityException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE_X509);
        Certificate targetCert = cf.generateCertificate(new ByteArrayInputStream(targetCertBytes));
        PublicKey targetPubKey = targetCert.getPublicKey();

        PrivateKey privKey = CryptoService.loadPrivateKey(keystorePath, keystorePass.toCharArray(), requestingUser);

        Map<String, byte[]> rewrappedMap = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : currentWrappedKeys.entrySet()) {
            String section = entry.getKey();
            byte[] wrappedForMe = entry.getValue();

            SecretKey secKey = CryptoService.unwrapKeyRSA(wrappedForMe, privKey);
            byte[] wrappedForTarget = CryptoService.wrapKeyRSA(secKey, targetPubKey);
            rewrappedMap.put(section, wrappedForTarget);
        }

        return rewrappedMap;
    }

    /**
     * Generates 256-bit AES keys for all house sections wrapped with the owner's public key.
     */
    public static Map<String, byte[]> generateAndWrapSectionKeys(String username, String keystorePath, String keystorePassword) 
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
        try (InputStream in = new FileInputStream(keystorePath)) {
            ks.load(in, keystorePassword.toCharArray());
        }

        Certificate cert = ks.getCertificate(username);
        if (cert == null) {
            Enumeration<String> aliases = ks.aliases();
            if (aliases.hasMoreElements()) {
                cert = ks.getCertificate(aliases.nextElement());
            }
        }
        if (cert == null) {
            throw new IllegalArgumentException("User certificate not found in keystore.");
        }

        PublicKey pubKey = cert.getPublicKey();
        String[] sections = {"E", "G", "L", "M", "P", "S"};
        Map<String, byte[]> wrappedKeys = new HashMap<>();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);

        for (String sec : sections) {
            SecretKey secKey = keyGen.generateKey();
            byte[] wrapped = CryptoService.wrapKeyRSA(secKey, pubKey);
            wrappedKeys.put(sec, wrapped);
        }

        return wrappedKeys;
    }

    /**
     * Retrieves the running SpertaClient.jar binary bytes for remote attestation.
     */
    public static byte[] loadRunningJarBytes() throws IOException, URISyntaxException {
        File codeSource = new File(ClientCryptoHelper.class.getProtectionDomain().getCodeSource().getLocation().toURI());

        if (codeSource.isFile() && codeSource.getName().endsWith(".jar")) {
            return Files.readAllBytes(codeSource.toPath());
        }

        Path defaultJar = Paths.get("SpertaClient.jar");
        if (Files.exists(defaultJar)) {
            return Files.readAllBytes(defaultJar);
        }

        Path binDirJar = Paths.get("bin", "SpertaClient.jar");
        if (Files.exists(binDirJar)) {
            return Files.readAllBytes(binDirJar);
        }

        throw new IOException("Binary SpertaClient.jar not found for attestation verification.");
    }

    /**
     * Generates a new PKCS12 keystore using a PBKDF2-derived password from the user login password,
     * and initializes a dedicated truststore containing only the CA/Server trust anchor.
     */
    public static void createNewUserKeystoreAndTruststore(String username, String userLoginPassword, String tsPassword) 
            throws GeneralSecurityException, IOException, InterruptedException {
        File usersDir = new File(KEYSTORE_DIR, USERS_SUBDIR);
        if (!usersDir.exists() && !usersDir.mkdirs()) {
            throw new IOException("Failed to create users directory: " + usersDir.getAbsolutePath());
        }

        File ksFile = new File(usersDir, "keystore." + username);
        File tsFile = new File(usersDir, "truststore." + username);

        if (ksFile.exists()) {
            throw new IllegalStateException("Keystore for user '" + username + "' already exists!");
        }

        // Derive technical keystore password from user login password
        char[] derivedKsPass = KeystoreManager.deriveKeystorePassword(username, userLoginPassword.toCharArray());
        String ksPassword = new String(derivedKsPass);
        // Resolve absolute keytool path to satisfy SonarQube java:S4036 (PATH injection prevention)[cite: 1]
        String keytoolBin = Paths.get(System.getProperty("java.home"), "bin", "keytool").toString();

        // 1. Generate user RSA keypair and certificate directly into PKCS12 Keystore
        String dname = "CN=" + username + ", OU=Sperta, O=FCUL, L=Lisbon, C=PT";
        ProcessBuilder pb = new ProcessBuilder(
                keytoolBin, "-genkeypair",
                "-alias", username,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365",
                "-keystore", ksFile.getAbsolutePath(),
                "-storepass", ksPassword,
                "-keypass", ksPassword,
                "-dname", dname,
                "-storetype", KEYSTORE_TYPE_PKCS12
        );
        pb.redirectErrorStream(true);
        Process p = pb.start();
        if (p.waitFor() != 0) {
            String errorMsg = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            throw new IllegalStateException("Failed to generate user keystore: " + errorMsg);
        }

        // 2. Locate the Server CA root certificate
        File caCert = new File("keystores/certServer.cert");
        if (!caCert.exists()) caCert = new File("data/certs/ca.crt");
        if (!caCert.exists()) caCert = new File("data/certs/server.crt");
        if (!caCert.exists()) caCert = new File("keystores/ca.crt");
        if (!caCert.exists()) caCert = new File("ca.crt");

        if (!caCert.exists()) {
            throw new FileNotFoundException("Server CA certificate not found (checked certServer.cert, ca.crt, server.crt). Unable to establish trust anchor.");
        }
        // 3. Create a clean Truststore populated exclusively with the CA / Server certificate
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        try (InputStream in = new FileInputStream(caCert)) {
            CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE_X509);
            Certificate cert = cf.generateCertificate(in);
            trustStore.setCertificateEntry("sperta-ca", cert);
        }

        char[] tsPassChars = (tsPassword != null && !tsPassword.isEmpty()) 
                ? tsPassword.toCharArray() 
                : "".toCharArray();

        try (OutputStream out = new FileOutputStream(tsFile)) {
            trustStore.store(out, tsPassChars);
        }
    }
}