package client;

import utils.CryptoService;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SpertaClient {

    private static final Logger LOGGER = Logger.getLogger(SpertaClient.class.getName());
    private static final int DEFAULT_PORT = 22345;
    private static final int CONNECTION_TIMEOUT_MILLIS = 10_000;
    private static final String DEFAULT_REFERENCE_JAR = "SpertaClient.jar";
    private static final int MAX_AUTH_ATTEMPTS = 3;

    public static void main(String[] args) {
        SpertaClient client = new SpertaClient();
        client.startClient(args);
    }

    public void startClient(String[] args) {
        if (args.length != 3 && args.length != 7) {
            LOGGER.log(Level.SEVERE, 
                    "Usage: java SpertaClient <serverAddress> <user-id> <password> "
                    + "or java SpertaClient <serverAddress> <truststore> <password-truststore> "
                    + "<keystore> <password-keystore> <user-id> <password>");
            return;
        }

        String serverAddressRaw = args[0];
        String truststorePath;
        String truststorePassword;
        String keystorePath;
        String keystorePassword;
        String username;
        String password;

        if (args.length == 3) {
            username = args[1];
            password = args[2];
            truststorePath = "keystores/users/truststore." + username;
            truststorePassword = getTruststorePassword();
            keystorePath = "keystores/users/keystore." + username;
            keystorePassword = new String(
                    KeystoreManager.deriveKeystorePassword(username, password.toCharArray()));
            try {
                KeystoreManager.ensureUserKeystoreExists(username, password.toCharArray());
            } catch (GeneralSecurityException | IOException e) {
                System.err.println("[ERROR] Could not prepare local security files: " + e.getMessage());
                return;
            }
        } else {
            truststorePath = args[1];
            truststorePassword = args[2];
            keystorePath = args[3];
            keystorePassword = args[4];
            username = args[5];
            password = args[6];
        }

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

        System.out.println();
        System.out.println("========================================");
        System.out.println("        SPERTA COMMAND-LINE CLIENT");
        System.out.println("========================================");
        System.out.println("Connecting to " + host + ":" + port + " as " + username + "...");

        try (Scanner scanner = new Scanner(System.in)) {
            connectAndExecute(host, port, username, password, keystorePath, keystorePassword, scanner);
        }
    }

    private String getTruststorePassword() {
        String envPassword = System.getenv("SPERTA_TRUSTSTORE_PASSWORD");
        if (envPassword != null && !envPassword.trim().isEmpty()) {
            return envPassword;
        }
        String propertyPassword = System.getProperty("sperta.truststore.password");
        return propertyPassword != null && !propertyPassword.trim().isEmpty()
                ? propertyPassword
                : "123456";
    }

    private void connectAndExecute(String host, int port, String username, String password,
                                   String keystorePath, String keystorePassword, Scanner scanner) {
        try {
            System.out.println("[INFO] Loading local keystore and truststore...");
            SSLContext sslContext = createSslContext(
                    keystorePath,
                    keystorePassword,
                    System.getProperty("javax.net.ssl.trustStore"),
                    System.getProperty("javax.net.ssl.trustStorePassword"));
            SSLSocketFactory sslFact = sslContext.getSocketFactory();

            System.out.println("[INFO] Connecting to server...");
            try (Socket plainSocket = new Socket()) {
                plainSocket.connect(
                        new InetSocketAddress(host, port),
                        CONNECTION_TIMEOUT_MILLIS);
                try (SSLSocket socket = (SSLSocket) sslFact.createSocket(
                        plainSocket, host, port, true)) {
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            socket.setSoTimeout(CONNECTION_TIMEOUT_MILLIS);
            System.out.println("[INFO] Starting TLS handshake...");
            socket.startHandshake();

            try (BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
                 PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), java.nio.charset.StandardCharsets.UTF_8), true)) {
                System.out.println("[OK] Secure connection established.");
                System.out.println("[OK] Client certificate accepted.");
                CommandHandler handler = new CommandHandler(
                        in, out, scanner, username, keystorePath, keystorePassword);
                handler.startLoop();
            }
            }
            }
        } catch (IOException e) {
            System.err.println("[ERROR] Network error: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.err.println("[ERROR] TLS configuration error: " + e.getMessage());
        }
    }

    private SSLContext createSslContext(
            String keystorePath,
            String keystorePassword,
            String truststorePath,
            String truststorePassword)
            throws GeneralSecurityException, IOException {
        File keystoreFile = new File(keystorePath);
        File truststoreFile = new File(truststorePath);
        if (!keystoreFile.isFile()) {
            throw new FileNotFoundException("Client keystore not found: " + keystoreFile.getPath());
        }
        if (!truststoreFile.isFile()) {
            throw new FileNotFoundException("Client truststore not found: " + truststoreFile.getPath());
        }

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(keystoreFile.toPath())) {
            keystore.load(input, keystorePassword.toCharArray());
        } catch (IOException e) {
            throw new IOException("Could not open client keystore. Check the username/password.", e);
        }

        KeyStore truststore = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(truststoreFile.toPath())) {
            truststore.load(input, truststorePassword.toCharArray());
        } catch (IOException e) {
            throw new IOException("Could not open client truststore. Check its password.", e);
        }

        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, keystorePassword.toCharArray());

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(truststore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null);
        return sslContext;
    }

}