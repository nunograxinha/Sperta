package client;

import utils.CryptoService;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SpertaClient {

    private static final Logger LOGGER = Logger.getLogger(SpertaClient.class.getName());
    private static final int DEFAULT_PORT = 22345;
    private static final String DEFAULT_REFERENCE_JAR = "SpertaClient.jar";
    private static final int MAX_AUTH_ATTEMPTS = 3;

    public static void main(String[] args) {
        SpertaClient client = new SpertaClient();
        client.startClient(args);
    }

    public void startClient(String[] args) {
        if (args.length != 7) {
            LOGGER.log(Level.SEVERE, 
                    "Usage: java SpertaClient <serverAddress> <truststore> <password-truststore> "
                    + "<keystore> <password-keystore> <user-id> <password>");
            return;
        }

        String serverAddressRaw = args[0];
        String truststorePath = args[1];
        String truststorePassword = args[2];
        String keystorePath = args[3];
        String keystorePassword = args[4];
        String username = args[5];
        String password = args[6];

        if (username.contains(":")) {
            LOGGER.log(Level.SEVERE, "Error: Username cannot contain the character ':'");
            return;
        }

        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePassword);

        String host = serverAddressRaw;
        int port = DEFAULT_PORT;

        if (serverAddressRaw.contains(":")) {
            String[] parts = serverAddressRaw.split(":");
            host = parts[0];
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.SEVERE, "Invalid port number specified in server address.");
                return;
            }
        }

        try (Scanner scanner = new Scanner(System.in)) {
            connectAndExecute(host, port, username, password, keystorePath, keystorePassword, scanner);
        }
    }

    private void connectAndExecute(String host, int port, String username, String password,
                                   String keystorePath, String keystorePassword, Scanner scanner) {
        SSLSocketFactory sslFact = (SSLSocketFactory) SSLSocketFactory.getDefault();

        try (SSLSocket socket = (SSLSocket) sslFact.createSocket(host, port)) {
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            socket.startHandshake();

            try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

                LOGGER.log(Level.INFO, "Connected securely to server at {0}:{1}", new Object[]{host, String.valueOf(port)});

                // STEP 1: Binary Attestation
                if (!doAttestation(outStream, inStream)) {
                    return;
                }

                // STEP 2: Authentication
                if (!doAuth(outStream, inStream, username, password, scanner, keystorePath, keystorePassword)) {
                    return;
                }

                // STEP 3: Command Interaction Loop
                CommandHandler handler = new CommandHandler(
                        outStream, inStream, scanner, username, keystorePath, keystorePassword);
                handler.startLoop();

            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Communication/Network I/O Error: {0}", e.getMessage());
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.SEVERE, "Protocol serialization error: {0}", e.getMessage());
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Security/Crypto configuration error: {0}", e.getMessage());
        }
    }

    private boolean doAttestation(ObjectOutputStream out, ObjectInputStream in)
            throws IOException, ClassNotFoundException {

        long nonce = in.readLong();
        LOGGER.log(Level.INFO, "Received attestation challenge nonce: {0}", nonce);

        byte[] calculatedHash;
        try {
            calculatedHash = calculateJarHashWithNonce(nonce);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error computing attestation hash: {0}", e.getMessage());
            calculatedHash = new byte[0];
        }

        out.writeObject(calculatedHash);
        out.flush();

        String response = (String) in.readObject();
        if ("OK-ATTEST".equals(response)) {
            LOGGER.log(Level.INFO, "Attestation OK");
            return true;
        } else {
            LOGGER.log(Level.WARNING, "Attestation FAILED: {0}", response);
            return false;
        }
    }

    private byte[] calculateJarHashWithNonce(long nonce) throws IOException, GeneralSecurityException {
        File jarFile;
        try {
            URI uri = SpertaClient.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            jarFile = new File(uri.getPath());
        } catch (Exception e) {
            jarFile = new File(DEFAULT_REFERENCE_JAR);
        }

        if (jarFile.isDirectory()) {
            jarFile = new File(DEFAULT_REFERENCE_JAR);
        }

        if (!jarFile.exists() || !jarFile.isFile()) {
            throw new FileNotFoundException("Client binary reference not found at: " + jarFile.getAbsolutePath());
        }

        byte[] jarBytes = Files.readAllBytes(jarFile.toPath());
        return CryptoService.computeHashWithNonce(nonce, jarBytes);
    }

    private boolean doAuth(ObjectOutputStream out, ObjectInputStream in,
                           String username, String password, Scanner scanner,
                           String keystorePath, String keystorePassword)
            throws IOException, ClassNotFoundException, GeneralSecurityException {

        String currentPassword = password;
        int attempts = 0;

        while (attempts < MAX_AUTH_ATTEMPTS) {
            attempts++;
            out.writeObject(username);
            out.writeObject(currentPassword);
            out.flush();

            Object response = in.readObject();
            AuthResult result = handleAuthStep(response, out, keystorePath, keystorePassword, username);

            if (result == AuthResult.SUCCESS) {
                return true;
            }
            if (result == AuthResult.FAILED_UNEXPECTED || attempts >= MAX_AUTH_ATTEMPTS) {
                break;
            }

            LOGGER.log(Level.INFO, "Try again. Password: ");
            if (!scanner.hasNextLine()) {
                return false;
            }
            currentPassword = scanner.nextLine().trim();
        }

        LOGGER.log(Level.SEVERE, "Authentication failed or maximum attempts exceeded.");
        return false;
    }

    private AuthResult handleAuthStep(Object response, ObjectOutputStream out,
                                     String keystorePath, String keystorePassword, String username)
            throws IOException, GeneralSecurityException {

        if (response instanceof String && "SEND-CERT".equals(response)) {
            LOGGER.log(Level.INFO, "OK-NEW-USER");
            byte[] certBytes = ClientCryptoHelper.loadUserCertificateBytes(keystorePath, keystorePassword, username);
            out.writeObject(certBytes);
            out.flush();
            LOGGER.log(Level.INFO, "Certificate dispatched to server.");
            return AuthResult.SUCCESS;
        }

        if (response instanceof Integer authStatus) {
            if (authStatus == 1) {
                LOGGER.log(Level.INFO, "OK-USER");
                return AuthResult.SUCCESS;
            }
            LOGGER.log(Level.WARNING, "WRONG-PWD");
            return AuthResult.RETRY;
        }

        LOGGER.log(Level.SEVERE, "Unexpected authentication response from server.");
        return AuthResult.FAILED_UNEXPECTED;
    }

    private enum AuthResult {
        SUCCESS,
        RETRY,
        FAILED_UNEXPECTED
    }
}