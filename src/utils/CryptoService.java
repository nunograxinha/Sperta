package utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class CryptoService {
    private static final String AES_ALGO = "AES";
    private static final String RSA_ALGO = "RSA";
    private static final String PBE_ALGO = "PBEWithHmacSHA256AndAES_128";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final int PBE_ITERATIONS = 100;

    // 1. Keystore and Key Management
    public static PrivateKey loadPrivateKey(String keystorePath, char[] password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password);
        }
        // Alias fallback logic omitted for brevity
        return (PrivateKey) ks.getKey(alias, password);
    }

    public static PublicKey getPublicKeyFromCertBytes(byte[] certBytes) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        return cert.getPublicKey();
    }

    // 2. Key Generation and Wrapping (E2E)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGO);
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static byte[] wrapKeyRSA(SecretKey aesKey, PublicKey rsaPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.WRAP_MODE, rsaPublicKey);
        return cipher.wrap(aesKey);
    }

    public static SecretKey unwrapKeyRSA(byte[] wrappedKey, PrivateKey rsaPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGO);
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, AES_ALGO, Cipher.SECRET_KEY);
    }

    // 3. Data Encryption and Decryption
    public static byte[] encryptAES(String plainText, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    public static String decryptAES(byte[] cipherText, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, "UTF-8");
    }

    public static byte[] encryptPBE(byte[] plainText, String password, byte[] salt) throws Exception {
        SecretKey key = derivePBEKey(password);
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(PBE_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, createPBEParameters(salt, iv));
        byte[] encrypted = cipher.doFinal(plainText);

        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    public static byte[] decryptPBE(byte[] cipherText, String password, byte[] salt) throws Exception {
        if (cipherText.length < 16) {
            throw new IllegalArgumentException("Encrypted data is too short to contain an IV");
        }

        byte[] iv = new byte[16];
        byte[] encrypted = new byte[cipherText.length - iv.length];
        System.arraycopy(cipherText, 0, iv, 0, iv.length);
        System.arraycopy(cipherText, iv.length, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(PBE_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, derivePBEKey(password), createPBEParameters(salt, iv));
        return cipher.doFinal(encrypted);
    }

    private static SecretKey derivePBEKey(String password) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        return SecretKeyFactory.getInstance(PBE_ALGO).generateSecret(keySpec);
    }

    private static PBEParameterSpec createPBEParameters(byte[] salt, byte[] iv) {
        return new PBEParameterSpec(salt, PBE_ITERATIONS, new IvParameterSpec(iv));
    }
}