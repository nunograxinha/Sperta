package client.gui;

import client.ClientCryptoHelper;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;

public class LoginView {

    private static final String USER_KEYSTORE_PREFIX = "keystores/users/keystore.";

    private final Stage stage;
    private final SpertaNetworkService networkService;

    private TextField hostField;
    private TextField portField;
    private TextField userField;
    private PasswordField passField;
    private Label statusLabel;
    private Button loginButton;

    public LoginView(Stage stage, SpertaNetworkService networkService) {
        this.stage = stage;
        this.networkService = networkService;
    }

    public Scene createScene() {
        Parent root = buildUI();
        Scene scene = new Scene(root, 480, 520);
        applyStyles(scene);
        return scene;
    }

    private void applyStyles(Scene scene) {
        URL cssUrl = getClass().getResource("/client/gui/styles.css");
        if (cssUrl == null) {
            cssUrl = getClass().getResource("styles.css");
        }
        if (cssUrl != null) {
            scene.getStylesheets().add(cssUrl.toExternalForm());
            return;
        }

        File localCss = new File("src/client/gui/styles.css");
        if (localCss.exists()) {
            scene.getStylesheets().add(localCss.toURI().toString());
        }
    }

    public Parent buildUI() {
        VBox root = new VBox(18);
        root.setPadding(new Insets(30));
        root.setAlignment(Pos.CENTER);
        root.setStyle("-fx-background-color: #ffffff;");

        Label titleLabel = new Label("Sperta Client Login");
        titleLabel.setStyle("-fx-font-size: 20px; -fx-font-weight: bold; -fx-text-fill: #0f172a;");

        GridPane grid = new GridPane();
        grid.setHgap(12);
        grid.setVgap(14);
        grid.setAlignment(Pos.CENTER);

        Label hostLabel = new Label("Server Host:");
        hostField = new TextField("localhost");
        grid.add(hostLabel, 0, 0);
        grid.add(hostField, 1, 0);

        Label portLabel = new Label("Port:");
        portField = new TextField("22345");
        grid.add(portLabel, 0, 1);
        grid.add(portField, 1, 1);

        Label userLabel = new Label("Username:");
        userField = new TextField("user1");
        grid.add(userLabel, 0, 2);
        grid.add(userField, 1, 2);

        Label passLabel = new Label("Password:");
        passField = new PasswordField();
        grid.add(passLabel, 0, 3);
        grid.add(passField, 1, 3);

        loginButton = new Button("Connect & Authenticate");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setStyle("-fx-background-color: #2563eb; -fx-text-fill: white; -fx-font-weight: bold; -fx-padding: 10 20; -fx-background-radius: 6;");
        loginButton.setOnAction(e -> handleLogin());

        Button createKeysBtn = new Button("Create New Keystore / Truststore");
        createKeysBtn.setMaxWidth(Double.MAX_VALUE);
        createKeysBtn.setStyle("-fx-background-color: #ffffff; -fx-text-fill: #334155; -fx-border-color: #cbd5e1; -fx-border-radius: 6; -fx-padding: 8 16;");
        createKeysBtn.setOnAction(e -> handleCreateKeystoreDialog());

        statusLabel = new Label();
        statusLabel.setWrapText(true);
        statusLabel.setMaxWidth(Double.MAX_VALUE);

        root.getChildren().addAll(titleLabel, grid, loginButton, createKeysBtn, statusLabel);
        return root;
    }

    private void handleLogin() {
        String host = hostField.getText().trim();
        String portStr = portField.getText().trim();
        String username = userField.getText().trim();
        String password = passField.getText();

        if (!hasRequiredFields(host, portStr, username, password, "Please fill in all fields.")) {
            return;
        }

        Integer port = parsePort(portStr);
        if (port == null) {
            return;
        }

        String keystorePath = USER_KEYSTORE_PREFIX + username;
        File ksFile = new File(keystorePath);
        if (!ksFile.exists()) {
            setStatus("Keystore not found for user '" + username + "'. Create it first below.", true);
            return;
        }

        loginButton.setDisable(true);
        setStatus("Connecting...", false);

        new Thread(() -> {
            try {
                networkService.initializeSecurity(username, password.toCharArray());

                Platform.runLater(() -> {
                    DashboardView dashboard = new DashboardView(networkService, stage, username);
                    stage.setScene(dashboard.createScene());
                    stage.setTitle("Sperta IoT Client - " + username);
                    stage.centerOnScreen();
                });
            } catch (GeneralSecurityException | IOException ex) {
                Platform.runLater(() -> {
                    loginButton.setDisable(false);
                    setStatus("Authentication failed: " + ex.getMessage(), true);
                });
            }
        }).start();
    }

    private void handleCreateKeystoreDialog() {
        String host = hostField.getText().trim();
        String portStr = portField.getText().trim();
        String username = userField.getText().trim();
        String password = passField.getText();

        if (!hasRequiredFields(host, portStr, username, password,
                "Please provide Host, Port, Username and Password before registering.")) {
            return;
        }

        Integer port = parsePort(portStr);
        if (port == null) {
            return;
        }

        setStatus("Registering user on server and generating keystores...", false);

        Runnable registerTask = () -> {
            try {
                String message = registerUserAndCreateKeys(host, port, username, password);
                Platform.runLater(() -> setStatus(message, false));
            } catch (InterruptedException e) {
                // SonarQube java:S2142 - Restore interrupted state
                Thread.currentThread().interrupt();
                Platform.runLater(() -> setStatus("Registration process was interrupted.", true));
            } catch (IOException | GeneralSecurityException | IllegalStateException ex) {
                Platform.runLater(() -> setStatus("Registration failed: " + ex.getMessage(), true));
            }
        };

        new Thread(registerTask).start();
    }

    private boolean hasRequiredFields(String host, String port, String username, String password,
                                      String errorMessage) {
        if (host.isEmpty() || port.isEmpty() || username.isEmpty() || password.isEmpty()) {
            setStatus(errorMessage, true);
            return false;
        }
        return true;
    }

    private Integer parsePort(String portText) {
        try {
            int port = Integer.parseInt(portText);
            if (port > 0 && port <= 65535) {
                return port;
            }
            setStatus("Port must be between 1 and 65535.", true);
        } catch (NumberFormatException e) {
            setStatus("Invalid port number.", true);
        }
        return null;
    }

    private String registerUserAndCreateKeys(String host, int port, String username, String password)
            throws IOException, GeneralSecurityException, InterruptedException {
        String response = networkService.registerUserOnServer(host, port, username, password);
        boolean alreadyRegistered = response.contains("User already exists");
        if (!response.startsWith("OK") && !alreadyRegistered) {
            throw new IllegalStateException("Server rejected registration: " + response);
        }

        String keystorePath = USER_KEYSTORE_PREFIX + username;
        if (!new File(keystorePath).exists()) {
            ClientCryptoHelper.createNewUserKeystoreAndTruststore(username, password, password);
        }
        String keystorePassword = new String(
                client.KeystoreManager.deriveKeystorePassword(username, password.toCharArray()));
        byte[] certificate = ClientCryptoHelper.extractUserCertificate(
                keystorePath, keystorePassword, username);
        String certificateResponse = networkService.registerUserCertificate(
                host, port, username, certificate);
        if (!certificateResponse.startsWith("OK")) {
            throw new IllegalStateException("Certificate registration failed: " + certificateResponse);
        }

        return alreadyRegistered
                ? "Local keys created for existing user '" + username + "'."
                : "User '" + username + "' registered on server and keys created!";
    }

    private void setStatus(String message, boolean isError) {
        statusLabel.setText(message);
        if (isError) {
            statusLabel.setStyle("-fx-background-color: #fef2f2; -fx-text-fill: #dc2626; -fx-padding: 8; -fx-background-radius: 6;");
        } else {
            statusLabel.setStyle("-fx-background-color: #ecfdf5; -fx-text-fill: #047857; -fx-padding: 8; -fx-background-radius: 6;");
        }
    }
}