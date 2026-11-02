package client;

import utils.CryptoService;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

/**
 * Handles client-side cryptographic operations, keystore/truststore management,
 * and End-to-End (E2E) section key wrapping/unwrapping.
 */
public final class ClientCryptoHelper {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String CERT_TYPE = "X.509";
    private static final String[] MANDATORY_SECTIONS = {"E", "G", "L", "M", "P", "S"};

    private ClientCryptoHelper() {
        // Utility class private constructor (java:S1118)
    }

    public static byte[] loadUserCertificateBytes(String keystorePath, String keystorePassword, String username)
            throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        Certificate cert = ks.getCertificate(username);
        if (cert == null) {
            Enumeration<String> aliases = ks.aliases();
            if (aliases.hasMoreElements()) {
                cert = ks.getCertificate(aliases.nextElement());
            }
        }
        return (cert != null) ? cert.getEncoded() : new byte[0];
    }

    public static Map<String, byte[]> generateAndWrapSectionKeys(String username, String ksPath, String ksPass)
            throws IOException, GeneralSecurityException {
        byte[] certBytes = loadUserCertificateBytes(ksPath, ksPass, username);
        if (certBytes.length == 0) {
            throw new GeneralSecurityException("Certificate not found in keystore for user: " + username);
        }

        PublicKey pubKey = CryptoService.getPublicKeyFromCertBytes(certBytes);
        Map<String, byte[]> map = new HashMap<>();

        for (String section : MANDATORY_SECTIONS) {
            SecretKey aesKey = CryptoService.generateAESKey();
            byte[] wrappedKey = CryptoService.wrapKeyRSA(aesKey, pubKey);
            map.put(section, wrappedKey);
        }
        return map;
    }

    public static Map<String, byte[]> rewrapSectionKeys(
            Map<String, byte[]> keysToWrap, byte[] targetCertBytes,
            String username, String ksPath, String ksPass)
            throws IOException, GeneralSecurityException {

        Map<String, byte[]> rewrappedMap = new HashMap<>();
        PrivateKey privKey = CryptoService.loadPrivateKey(ksPath, ksPass.toCharArray(), username);
        PublicKey targetPubKey = CryptoService.getPublicKeyFromCertBytes(targetCertBytes);

        for (Map.Entry<String, byte[]> entry : keysToWrap.entrySet()) {
            SecretKey rawKey = CryptoService.unwrapKeyRSA(entry.getValue(), privKey);
            byte[] newWrappedBytes = CryptoService.wrapKeyRSA(rawKey, targetPubKey);
            rewrappedMap.put(entry.getKey(), newWrappedBytes);
        }
        return rewrappedMap;
    }

    public static void saveCertificateToTrustStore(String trustStorePath, String trustStorePass,
                                                   String alias, byte[] certBytes)
            throws IOException, GeneralSecurityException {
        CertificateFactory certFactory = CertificateFactory.getInstance(CERT_TYPE);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        KeyStore ts = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            ts.load(fis, trustStorePass.toCharArray());
        }

        ts.setCertificateEntry(alias, cert);

        try (FileOutputStream fos = new FileOutputStream(trustStorePath)) {
            ts.store(fos, trustStorePass.toCharArray());
        }
    }
}