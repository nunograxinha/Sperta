package client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
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

    static {
        configureConsoleLogging();
    }

    private static void configureConsoleLogging() {
        Logger rootLogger = Logger.getLogger("");
        for (Handler handler : rootLogger.getHandlers()) {
            handler.setFormatter(new Formatter() {
                @Override
                public String format(LogRecord logRecord) {
                    return formatMessage(logRecord) + System.lineSeparator();
                }
            });
        }
    }

    public static void main(String[] args) {
        SpertaClient client = new SpertaClient();
        client.startClient(args);
    }

    public void startClient(String[] args) {
        if (args.length != 3) {
            LOGGER.log(Level.SEVERE,
                    "Usage: java SpertaClient <serverAddress> <user-id> <password>");
            return;
        }

        String serverAddressRaw = args[0];
        String username = args[1];
        String password = args[2];
        String truststorePath = "keystores/users/truststore." + username;
        String truststorePassword = getTruststorePassword();
        String keystorePath = "keystores/users/keystore." + username;
        String keystorePassword = new String(
                KeystoreManager.deriveKeystorePassword(username, password.toCharArray()));
        try {
            KeystoreManager.ensureUserKeystoreExists(username, password.toCharArray());
        } catch (GeneralSecurityException | IOException e) {
            LOGGER.log(Level.SEVERE, "[ERROR] Could not prepare local security files: {0}", e.getMessage());
            return;
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

        LOGGER.info("");
        LOGGER.info("========================================");
        LOGGER.info("        SPERTA COMMAND-LINE CLIENT");
        LOGGER.info("========================================");
        LOGGER.log(Level.INFO, "Connecting to {0}:{1} as {2}...", new Object[]{host, port, username});

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
            LOGGER.info("[INFO] Loading local keystore and truststore...");
            SSLContext sslContext = createSslContext(
                    keystorePath,
                    keystorePassword,
                    System.getProperty("javax.net.ssl.trustStore"),
                    System.getProperty("javax.net.ssl.trustStorePassword"));
            SSLSocketFactory sslFact = sslContext.getSocketFactory();

            LOGGER.info("[INFO] Connecting to server...");
            try (Socket plainSocket = new Socket()) {
                plainSocket.connect(
                        new InetSocketAddress(host, port),
                        CONNECTION_TIMEOUT_MILLIS);
                try (SSLSocket socket = (SSLSocket) sslFact.createSocket(
                        plainSocket, host, port, true)) {
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            socket.setSoTimeout(CONNECTION_TIMEOUT_MILLIS);
            LOGGER.info("[INFO] Starting TLS handshake...");
            socket.startHandshake();

            try (BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
                 PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), java.nio.charset.StandardCharsets.UTF_8), true)) {
                LOGGER.info("[OK] Secure connection established.");
                LOGGER.info("[OK] Client certificate accepted.");
                authenticate(in, out, username, password);
                CommandHandler handler = new CommandHandler(
                        in, out, scanner, username, keystorePath, keystorePassword);
                handler.startLoop();
            }
            }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "[ERROR] Network error: {0}", e.getMessage());
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "[ERROR] TLS configuration error: {0}", e.getMessage());
        }
    }

    private void authenticate(BufferedReader in, PrintWriter out, String username, String password)
            throws IOException {
        out.println("AUTH " + username + " " + password);
        String response = in.readLine();
        if (response == null || !response.startsWith("OK:AUTHENTICATED")) {
            throw new IOException(response == null ? "Server closed the connection during authentication."
                    : response);
        }
        LOGGER.info("[OK] User authenticated.");
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