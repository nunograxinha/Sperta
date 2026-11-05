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
import java.net.URL;

public class LoginView {

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

        if (host.isEmpty() || portStr.isEmpty() || username.isEmpty() || password.isEmpty()) {
            setStatus("Please fill in all fields.", true);
            return;
        }

        try {
            int port = Integer.parseInt(portStr);
            if (port <= 0 || port > 65535) {
                setStatus("Port must be between 1 and 65535.", true);
                return;
            }
        } catch (NumberFormatException e) {
            setStatus("Invalid port number.", true);
            return;
        }

        String keystorePath = "keystores/users/keystore." + username;
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
            } catch (Exception ex) {
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

        if (host.isEmpty() || portStr.isEmpty() || username.isEmpty() || password.isEmpty()) {
            setStatus("Please provide Host, Port, Username and Password before registering.", true);
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
            if (port <= 0 || port > 65535) {
                setStatus("Port must be between 1 and 65535.", true);
                return;
            }
        } catch (NumberFormatException e) {
            setStatus("Invalid port number.", true);
            return;
        }

        setStatus("Registering user on server and generating keystores...", false);

        Runnable registerTask = () -> {
            try {
                // 1. Register credentials on server
                String response = networkService.registerUserOnServer(host, port, username, password);
                if (!response.startsWith("OK")) {
                    Platform.runLater(() -> setStatus("Server rejected registration: " + response, true));
                    return;
                }

                // 2. Generate local user keystore with derived key and truststore
                ClientCryptoHelper.createNewUserKeystoreAndTruststore(username, password, password);
                byte[] certificate = ClientCryptoHelper.extractUserCertificate(
                        "keystores/users/keystore." + username,
                        new String(client.KeystoreManager.deriveKeystorePassword(username, password.toCharArray())),
                        username);
                String certificateResponse = networkService.registerUserCertificate(
                        host, port, username, certificate);
                if (!certificateResponse.startsWith("OK")) {
                    Platform.runLater(() -> setStatus("Certificate registration failed: "
                            + certificateResponse, true));
                    return;
                }

                Platform.runLater(() -> setStatus("User '" + username + "' registered on server and keys created!", false));
            } catch (InterruptedException e) {
                // SonarQube java:S2142 - Restore interrupted state
                Thread.currentThread().interrupt();
                Platform.runLater(() -> setStatus("Registration process was interrupted.", true));
            } catch (Exception ex) {
                Platform.runLater(() -> setStatus("Registration failed: " + ex.getMessage(), true));
            }
        };

        new Thread(registerTask).start();
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