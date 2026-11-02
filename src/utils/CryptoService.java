package utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoService {

    private static final String AES_KEY_ALGO = "AES";
    private static final String AES_CIPHER_ALGO = "AES/GCM/NoPadding";
    private static final String RSA_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final String HASH_ALGO = "SHA-256";
    private static final String KEYSTORE_TYPE = "PKCS12";

    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int AES_KEY_BITS = 128;
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended by NIST
    private static final int GCM_TAG_LENGTH = 128; // 128-bit AEAD integrity authentication tag
    private static final int SALT_LENGTH = 16;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoService() {
        // Utility class private constructor to satisfy SonarQube rule java:S1118
    }

    // 1. Keystore and Key Management
    public static PrivateKey loadPrivateKey(String keystorePath, char[] password, String alias) 
            throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password);
        }
        if (alias != null && ks.containsAlias(alias)) {
            return (PrivateKey) ks.getKey(alias, password);
        }
        Enumeration<String> aliases = ks.aliases();
        if (aliases.hasMoreElements()) {
            return (PrivateKey) ks.getKey(aliases.nextElement(), password);
        }
        throw new KeyStoreException("No valid key alias found in keystore.");
    }

    public static PublicKey getPublicKeyFromCertBytes(byte[] certBytes) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        return cert.getPublicKey();
    }

    // 2. Key Generation and RSA Key Wrapping (E2E)
    public static SecretKey generateAESKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_KEY_ALGO);
        keyGen.init(AES_KEY_BITS);
        return keyGen.generateKey();
    }

    public static byte[] wrapKeyRSA(SecretKey aesKey, PublicKey rsaPublicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.WRAP_MODE, rsaPublicKey);
        return cipher.wrap(aesKey);
    }

    public static SecretKey unwrapKeyRSA(byte[] wrappedKey, PrivateKey rsaPrivateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, AES_KEY_ALGO, Cipher.SECRET_KEY);
    }

    // 3. Symmetric Authenticated Encryption (AES-GCM)
    public static byte[] encryptAES(String plainText, SecretKey aesKey) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
        return result;
    }

    public static String decryptAES(byte[] cipherTextWithIv, SecretKey aesKey) throws GeneralSecurityException {
        if (cipherTextWithIv.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data is too short to contain a valid GCM IV");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] cipherText = new byte[cipherTextWithIv.length - iv.length];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);
        System.arraycopy(cipherTextWithIv, iv.length, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // 4. Password-Based Encryption (PBE using PBKDF2 + AES-GCM)
    public static byte[] encryptPBE(byte[] plainText, String password, byte[] salt) throws GeneralSecurityException {
        SecretKey key = derivePBEKey(password, salt);
        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] encrypted = cipher.doFinal(plainText);

        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    public static byte[] decryptPBE(byte[] cipherTextWithIv, String password, byte[] salt) throws GeneralSecurityException {
        if (cipherTextWithIv.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data is too short to contain a valid GCM IV");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encrypted = new byte[cipherTextWithIv.length - iv.length];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);
        System.arraycopy(cipherTextWithIv, iv.length, encrypted, 0, encrypted.length);

        SecretKey key = derivePBEKey(password, salt);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return cipher.doFinal(encrypted);
    }

    // 5. Hashing, Salts, and Nonces
    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] computeSHA256(byte[] data) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);
        return digest.digest(data);
    }

    public static byte[] computeHashWithNonce(long nonce, byte[] data) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(nonce);
        digest.update(buffer.array());
        digest.update(data);
        return digest.digest();
    }

    private static SecretKey derivePBEKey(String password, byte[] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, AES_KEY_ALGO);
    }
}