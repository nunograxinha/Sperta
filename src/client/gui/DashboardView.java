package client.gui;

import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Separator;
import javafx.scene.control.Slider;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.File;
import java.awt.Desktop;
import java.io.IOException;
import java.net.URL;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DashboardView {

    private static final Logger LOGGER = Logger.getLogger(DashboardView.class.getName());

    private static final String PRIMARY_BUTTON_STYLE = "primary-button";
    private static final String SECTION_HEADER_STYLE = "-fx-font-weight: bold; -fx-text-fill: #0f172a;";
    private static final String ERROR_PREFIX = "Error: ";

    private static final String STATUS_STYLE_SUCCESS = 
            "-fx-background-color: #ecfdf5; -fx-text-fill: #047857; -fx-padding: 8; -fx-background-radius: 6;";
    private static final String STATUS_STYLE_ERROR = 
            "-fx-background-color: #fef2f2; -fx-text-fill: #dc2626; -fx-padding: 8; -fx-background-radius: 6;";

    private final SpertaNetworkService networkService;
    private final Stage stage;
    private final String username;

    private final ObservableList<String> availableHouses = FXCollections.observableArrayList();
    private final ObservableList<DeviceViewModel> devicesList = FXCollections.observableArrayList();

    private String selectedHouse = "";

    private Label currentHouseLabel;
    private Label feedbackLabel;
    private VBox houseButtonsBox;
    private TableView<DeviceViewModel> devicesTable;

    private ComboBox<String> registerSectionCombo;
    private TextField targetUserField;
    private ComboBox<String> grantSectionCombo;
    private Slider valueSlider;
    private TextField valueTextField;

    private Timeline autoRefreshTimeline;

    private Label statusLabel;

    public DashboardView(SpertaNetworkService networkService, Stage stage, String username) {
        this.networkService = networkService;
        this.stage = stage;
        this.username = username;
    }

    public Scene createScene() {
        Parent root = buildUI();
        Scene scene = new Scene(root, 1080, 760);
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
        BorderPane root = new BorderPane();
        root.getStyleClass().add("dashboard-root");

        root.setTop(buildTopBar());
        root.setLeft(buildLeftNav());
        root.setCenter(buildCenterContent());
        root.setRight(buildRightControlPanel());

        loadHouses();
        setupSilentAutoRefresh();

        return root;
    }

    private HBox buildTopBar() {
        HBox topBar = new HBox(12);
        topBar.setPadding(new Insets(12, 20, 12, 20));
        topBar.setAlignment(Pos.CENTER_LEFT);
        topBar.getStyleClass().add("top-bar");

        currentHouseLabel = new Label("Selected House: None");
        currentHouseLabel.setStyle("-fx-font-size: 14px; -fx-font-weight: bold; -fx-text-fill: #0f172a;");

        Button refreshBtn = new Button("Refresh (RT)");
        refreshBtn.setOnAction(e -> refreshAll());

        Button openRtBtn = new Button("Open RT File");
        openRtBtn.setOnAction(e -> handleOpenRtFile());

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label userLabel = new Label("User: " + username);
        userLabel.setStyle("-fx-text-fill: #334155; -fx-font-weight: bold;");

        Button logoutBtn = new Button("Logout");
        logoutBtn.setOnAction(e -> handleLogout());

        topBar.getChildren().addAll(currentHouseLabel, refreshBtn, openRtBtn, spacer, userLabel, logoutBtn);
        return topBar;
    }

    private VBox buildLeftNav() {
        VBox leftNav = new VBox(8);
        leftNav.setPadding(new Insets(12));
        leftNav.setPrefWidth(210);
        leftNav.getStyleClass().add("left-nav");

        Label navTitle = new Label("Accessible Houses");
        navTitle.setStyle("-fx-font-weight: bold; -fx-text-fill: #0f172a; -fx-font-size: 13px;");

        Button discoverBtn = new Button("Discover Houses");
        discoverBtn.setMaxWidth(Double.MAX_VALUE);
        discoverBtn.setOnAction(e -> loadHouses());

        houseButtonsBox = new VBox(5);

        ScrollPane houseScroll = new ScrollPane(houseButtonsBox);
        houseScroll.setFitToWidth(true);
        houseScroll.setStyle("-fx-background-color: transparent; -fx-background: transparent; -fx-border-color: transparent;");
        houseScroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        VBox.setVgrow(houseScroll, Priority.ALWAYS);

        TextField newHouseField = new TextField();
        newHouseField.setPromptText("New house name");

        Button createHouseBtn = new Button("Create House");
        createHouseBtn.getStyleClass().add(PRIMARY_BUTTON_STYLE);
        createHouseBtn.setMaxWidth(Double.MAX_VALUE);
        createHouseBtn.setOnAction(e -> handleCreateHouse(newHouseField));

        leftNav.getChildren().addAll(navTitle, discoverBtn, houseScroll, newHouseField, createHouseBtn);
        return leftNav;
    }

    @SuppressWarnings("deprecation")
    private VBox buildCenterContent() {
        VBox centerBox = new VBox(10);
        centerBox.setPadding(new Insets(12));
        VBox.setVgrow(centerBox, Priority.ALWAYS);

        devicesTable = new TableView<>(devicesList);
        devicesTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        VBox.setVgrow(devicesTable, Priority.ALWAYS);

        TableColumn<DeviceViewModel, String> idCol = new TableColumn<>("Device ID");
        idCol.setCellValueFactory(data -> data.getValue().deviceIdProperty());

        TableColumn<DeviceViewModel, String> secCol = new TableColumn<>("Section");
        secCol.setCellValueFactory(data -> data.getValue().sectionProperty());

        TableColumn<DeviceViewModel, String> valCol = new TableColumn<>("State / Timer");
        valCol.setCellValueFactory(data -> data.getValue().valueProperty());
        valCol.setCellFactory(col -> createStatusCell());

        devicesTable.getColumns().add(idCol);
        devicesTable.getColumns().add(secCol);
        devicesTable.getColumns().add(valCol);

        devicesTable.getSelectionModel().selectedItemProperty().addListener((obs, oldV, newV) -> syncControlsWithSelection(newV));

        centerBox.getChildren().add(devicesTable);
        return centerBox;
    }

    private TableCell<DeviceViewModel, String> createStatusCell() {
        return new TableCell<>() {
            @Override
            protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                if (empty || val == null) {
                    setText(null);
                    setStyle("");
                    return;
                }

                String text = val.trim();
                setText(text);

                if ("OFF".equalsIgnoreCase(text)) {
                    setStyle("-fx-text-fill: #64748b; -fx-font-weight: bold;");
                } else if (text.startsWith("ON")) {
                    setStyle("-fx-text-fill: #16a34a; -fx-font-weight: bold;");
                } else {
                    setStyle("");
                }
            }
        };
    }

    private void syncControlsWithSelection(DeviceViewModel selected) {
        if (selected == null) {
            return;
        }
        try {
            int num = selected.getInitialMinutes();
            if (num >= 0) {
                valueSlider.setValue(num);
                valueTextField.setText(String.valueOf(num));
            }
        } catch (Exception ignored) {
            // Keep previous values
        }
    }

    private ScrollPane buildRightControlPanel() {
        VBox right = new VBox(10);
        right.setPadding(new Insets(12));
        right.setPrefWidth(280);
        right.setStyle("-fx-background-color: #ffffff;");

        Label rdTitle = new Label("Register Device (RD)");
        rdTitle.setStyle(SECTION_HEADER_STYLE);

        registerSectionCombo = new ComboBox<>(FXCollections.observableArrayList("M", "E", "L", "G", "S", "P"));
        registerSectionCombo.setValue("M");
        registerSectionCombo.setMaxWidth(Double.MAX_VALUE);

        Button addDeviceBtn = new Button("Add Device to Section");
        addDeviceBtn.getStyleClass().add(PRIMARY_BUTTON_STYLE);
        addDeviceBtn.setMaxWidth(Double.MAX_VALUE);
        addDeviceBtn.setOnAction(e -> handleRegisterDevice());

        Label addTitle = new Label("Grant Access (ADD)");
        addTitle.setStyle(SECTION_HEADER_STYLE);

        targetUserField = new TextField();
        targetUserField.setPromptText("Target username (e.g. user1)");

        grantSectionCombo = new ComboBox<>(FXCollections.observableArrayList("ALL", "M", "E", "L", "G", "S", "P"));
        grantSectionCombo.setValue("ALL");
        grantSectionCombo.setMaxWidth(Double.MAX_VALUE);

        Button grantBtn = new Button("Grant Section Access");
        grantBtn.getStyleClass().add(PRIMARY_BUTTON_STYLE);
        grantBtn.setMaxWidth(Double.MAX_VALUE);
        grantBtn.setOnAction(e -> handleGrantAccess());

        Label ecTitle = new Label("Set Value (EC: 0 - 600)");
        ecTitle.setStyle(SECTION_HEADER_STYLE);

        valueSlider = new Slider(0, 600, 0);
        valueSlider.setShowTickLabels(false);
        valueSlider.setShowTickMarks(false);

        valueTextField = new TextField("0");

        valueSlider.valueProperty().addListener((obs, oldV, newV) ->
                valueTextField.setText(String.valueOf(newV.intValue()))
        );

        valueTextField.textProperty().addListener((obs, oldV, newV) -> {
            try {
                int val = Integer.parseInt(newV.trim());
                if (val >= 0 && val <= 600) {
                    valueSlider.setValue(val);
                }
            } catch (NumberFormatException ignored) {
                // Ignore while user is typing
            }
        });

        Button applyValBtn = new Button("Apply Value");
        applyValBtn.getStyleClass().add(PRIMARY_BUTTON_STYLE);
        applyValBtn.setMaxWidth(Double.MAX_VALUE);
        applyValBtn.setOnAction(e -> handleApplyValue());

        Label rhTitle = new Label("History Report (RH)");
        rhTitle.setStyle(SECTION_HEADER_STYLE);

        Button openCsvBtn = new Button("Open Device CSV History");
        openCsvBtn.setMaxWidth(Double.MAX_VALUE);
        openCsvBtn.setOnAction(e -> handleDownloadHistory());

        feedbackLabel = new Label("Ready");
        feedbackLabel.setWrapText(true);
        feedbackLabel.setStyle(STATUS_STYLE_SUCCESS);
        feedbackLabel.setMaxWidth(Double.MAX_VALUE);

        right.getChildren().addAll(
                rdTitle, registerSectionCombo, addDeviceBtn,
                new Separator(),
                addTitle, targetUserField, grantSectionCombo, grantBtn,
                new Separator(),
                ecTitle, valueSlider, valueTextField, applyValBtn,
                new Separator(),
                rhTitle, openCsvBtn,
                feedbackLabel
        );

        ScrollPane scrollPane = new ScrollPane(right);
        scrollPane.setFitToWidth(true);
        scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scrollPane.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);
        scrollPane.setStyle("-fx-background-color: #ffffff; -fx-background: #ffffff; -fx-border-color: #e2e8f0; -fx-border-width: 0 0 0 1;");

        return scrollPane;
    }

    private void loadHouses() {
        new Thread(() -> {
            try {
                List<String> houses = networkService.fetchAccessibleHouses();
                houses.sort(this::compareNatural);

                Platform.runLater(() -> {
                    availableHouses.clear();
                    availableHouses.addAll(houses);

                    if (availableHouses.isEmpty()) {
                        selectedHouse = "";
                        currentHouseLabel.setText("Selected House: None");
                        devicesList.clear();
                    } else if (selectedHouse.isEmpty() || !availableHouses.contains(selectedHouse)) {
                        selectedHouse = availableHouses.get(0);
                        currentHouseLabel.setText("Selected House: " + selectedHouse);
                    }

                    renderHouseButtons();

                    if (!selectedHouse.isEmpty()) {
                        refreshDevices();
                    }
                });
            } catch (IOException e) {
                Platform.runLater(() -> setStatus("Failed to load houses: " + e.getMessage(), true));
            }
        }).start();
    }

    /**
     * Updates the status bar/label with feedback messages.
     *
     * @param message The text message to display.
     * @param isError True to style as an error, false for success/info.
     */
    private void setStatus(String message, boolean isError) {
        if (statusLabel != null) {
            statusLabel.setText(message);
            statusLabel.setStyle(isError ? STATUS_STYLE_ERROR : STATUS_STYLE_SUCCESS);
        } else {
            if (isError) {
                LOGGER.log(Level.SEVERE, "[Dashboard Error] {0}", message);
            } else {
                LOGGER.log(Level.INFO, "[Dashboard Info] {0}", message);
            }
        }
    }

    private void renderHouseButtons() {
        houseButtonsBox.getChildren().clear();
        for (String house : availableHouses) {
            Button btn = new Button(house);
            btn.setMaxWidth(Double.MAX_VALUE);
            if (house.equals(selectedHouse)) {
                btn.getStyleClass().add("house-btn-selected");
            } else {
                btn.getStyleClass().add("house-btn");
            }
            btn.setOnAction(e -> {
                selectedHouse = house;
                devicesList.clear();
                currentHouseLabel.setText("Selected House: " + selectedHouse);
                renderHouseButtons();
                refreshDevices();
            });
            houseButtonsBox.getChildren().add(btn);
        }
    }

    private void refreshAll() {
        loadHouses();
        setFeedback("Refreshing data...", false);
    }

    private void refreshDevices() {
        if (selectedHouse.isEmpty()) {
            devicesList.clear();
            return;
        }

        String houseToRefresh = selectedHouse;
        new Thread(() -> {
            try {
                List<DeviceViewModel> updated = networkService.fetchDevicesStatus(houseToRefresh);
                updated.sort((d1, d2) -> compareNatural(d1.getDeviceId(), d2.getDeviceId()));

                Platform.runLater(() -> {
                    if (!houseToRefresh.equals(selectedHouse)) {
                        return;
                    }
                    devicesList.setAll(updated);

                    for (DeviceViewModel device : devicesList) {
                        device.updateDisplayState();
                    }

                    devicesTable.refresh();
                    setFeedback("Loaded " + devicesList.size() + " authorized device(s).", false);
                });
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, ex, () -> "Failed to refresh device status for house: " + selectedHouse);
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void setupSilentAutoRefresh() {
        autoRefreshTimeline = new Timeline(new KeyFrame(Duration.seconds(5), event -> {
            if (selectedHouse != null && !selectedHouse.isEmpty()) {
                refreshDevicesSilently();
            }
        }));
        autoRefreshTimeline.setCycleCount(Animation.INDEFINITE);
        autoRefreshTimeline.play();
    }

    private void refreshDevicesSilently() {
        String houseToRefresh = selectedHouse;
        new Thread(() -> {
            try {
                List<DeviceViewModel> updated = networkService.fetchDevicesStatus(houseToRefresh);
                Platform.runLater(() -> {
                    if (houseToRefresh.equals(selectedHouse)) {
                        applyDeviceUpdates(updated);
                    }
                });
            } catch (Exception ignored) {
                // Silent catch for background pooling
            }
        }).start();
    }

    private void applyDeviceUpdates(List<DeviceViewModel> updated) {
        boolean changed = false;
        for (DeviceViewModel model : updated) {
            if (updateDeviceIfPresent(model)) {
                changed = true;
            }
        }

        for (DeviceViewModel device : devicesList) {
            device.updateDisplayState();
        }

        if (changed || !devicesList.isEmpty()) {
            devicesTable.refresh();
        }
    }

    private boolean updateDeviceIfPresent(DeviceViewModel model) {
        for (DeviceViewModel current : devicesList) {
            if (current.getDeviceId().equalsIgnoreCase(model.getDeviceId())) {
                if (current.getInitialMinutes() != model.getInitialMinutes()) {
                    current.setInitialMinutes(model.getInitialMinutes());
                    current.setLastCommandTimestamp(model.getLastCommandTimestamp());
                    current.updateDisplayState();
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    private void refreshDevicesWithoutFeedback() {
        if (selectedHouse.isEmpty()) {
            return;
        }
        String houseToRefresh = selectedHouse;
        new Thread(() -> {
            try {
                List<DeviceViewModel> updated = networkService.fetchDevicesStatus(houseToRefresh);
                updated.sort((d1, d2) -> compareNatural(d1.getDeviceId(), d2.getDeviceId()));

                Platform.runLater(() -> {
                    if (!houseToRefresh.equals(selectedHouse)) {
                        return;
                    }
                    devicesList.setAll(updated);

                    for (DeviceViewModel device : devicesList) {
                        device.updateDisplayState();
                    }

                    devicesTable.refresh();
                });
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, ex, () -> "Failed refreshing devices: " + selectedHouse);
            }
        }).start();
    }

    private void handleCreateHouse(TextField nameField) {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            setFeedback("Please enter a valid house name.", true);
            return;
        }

        new Thread(() -> {
            try {
                String result = networkService.createHouse(name);
                Platform.runLater(() -> {
                    nameField.clear();
                    setFeedback("Create House: " + result, false);
                    loadHouses();
                });
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Could not create house " + name);
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void handleRegisterDevice() {
        if (selectedHouse.isEmpty()) {
            setFeedback("Select a house first.", true);
            return;
        }
        String section = registerSectionCombo.getValue();

        new Thread(() -> {
            try {
                String res = networkService.registerDevice(selectedHouse, section);
                Platform.runLater(() -> {
                    String cleanRes = (res != null) ? res.trim() : "";
                    String upperRes = cleanRes.toUpperCase();

                    boolean isError = cleanRes.isEmpty()
                            || upperRes.startsWith("NO")
                            || upperRes.contains("ERROR")
                            || upperRes.contains("DENIED")
                            || upperRes.contains("NOT AUTHORIZED");

                    if (isError) {
                        setFeedback("Permission denied: cannot add device to section " + section + " (" + cleanRes + ")", true);
                    } else {
                        setFeedback("Device registered successfully: " + cleanRes, false);
                        refreshDevicesWithoutFeedback();
                    }
                });
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Failed registering device in " + section);
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void handleGrantAccess() {
        if (selectedHouse.isEmpty()) {
            setFeedback("Select a house first.", true);
            return;
        }
        String targetUser = targetUserField.getText().trim();
        String section = grantSectionCombo.getValue();

        if (targetUser.isEmpty()) {
            setFeedback("Target username is required.", true);
            return;
        }

        new Thread(() -> {
            try {
                String res = networkService.addUserAccess(selectedHouse, targetUser, section);
                Platform.runLater(() -> {
                    targetUserField.clear();
                    String cleanRes = (res != null) ? res.trim() : "";
                    String upperRes = cleanRes.toUpperCase();

                    boolean isError = cleanRes.isEmpty()
                            || upperRes.startsWith("NO")
                            || upperRes.contains("ERROR")
                            || upperRes.contains("DENIED")
                            || upperRes.contains("NOT AUTHORIZED");

                    if (isError) {
                        setFeedback("Permission denied: cannot grant access (" + cleanRes + ")", true);
                    } else {
                        setFeedback("Access granted: " + cleanRes, false);
                    }
                });
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Failed granting access to " + targetUser);
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void handleApplyValue() {
        DeviceViewModel selected = devicesTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            setFeedback("Select a device in the table first.", true);
            return;
        }

        int val;
        try {
            val = Integer.parseInt(valueTextField.getText().trim());
        } catch (NumberFormatException e) {
            setFeedback("Value must be between 0 and 600.", true);
            return;
        }

        final int targetVal = val;
        new Thread(() -> {
            try {
                String resp = networkService.executeCommand(selectedHouse, selected.getDeviceId(), targetVal);
                Platform.runLater(() -> {
                    if ("OK".equalsIgnoreCase(resp.trim())) {
                        setFeedback("Command sent: OK", false);
                        selected.updateTimer(targetVal);
                        devicesTable.refresh();
                    } else {
                        setFeedback("Command sent: " + resp, true);
                    }
                });
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Failed sending command to " + selected.getDeviceId());
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void handleDownloadHistory() {
        DeviceViewModel selected = devicesTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            setFeedback("Select a device in the table first.", true);
            return;
        }

        new Thread(() -> {
            try {
                File historyFile = networkService.fetchDeviceHistory(selectedHouse, selected.getDeviceId());
                Platform.runLater(() -> {
                    try {
                        if (!Desktop.isDesktopSupported()) {
                            throw new IOException("Desktop file opening is not supported.");
                        }
                        Desktop.getDesktop().open(historyFile);
                        setFeedback("Opened: " + historyFile.getName(), false);
                    } catch (IOException ex) {
                        setFeedback(ERROR_PREFIX + ex.getMessage(), true);
                    }
                });
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Failed retrieving history for " + selected.getDeviceId());
                Platform.runLater(() -> setFeedback(ERROR_PREFIX + ex.getMessage(), true));
            }
        }).start();
    }

    private void handleOpenRtFile() {
        if (selectedHouse.isEmpty() || devicesList.isEmpty()) {
            setFeedback("No devices available for selected house.", true);
            return;
        }

        try {
            File saved = networkService.saveStatusToFile(selectedHouse, devicesList);
            if (!Desktop.isDesktopSupported()) {
                throw new IOException("Desktop file opening is not supported.");
            }
            Desktop.getDesktop().open(saved);
            setFeedback("Opened RT file: " + saved.getName(), false);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE, ex, () -> "Failed writing RT file");
            setFeedback(ERROR_PREFIX + ex.getMessage(), true);
        }
    }

    private void handleLogout() {
        if (autoRefreshTimeline != null) {
            autoRefreshTimeline.stop();
        }
        networkService.disconnect();

        LoginView loginView = new LoginView(stage, networkService);
        stage.setScene(loginView.createScene());
        stage.setTitle("Sperta Client Login");
        stage.centerOnScreen();
    }

    private void setFeedback(String message, boolean isError) {
        feedbackLabel.setText(message);
        if (isError) {
            feedbackLabel.setStyle("-fx-background-color: #fef2f2; -fx-text-fill: #dc2626; -fx-padding: 8; -fx-background-radius: 6; -fx-font-weight: bold;");
        } else {
            feedbackLabel.setStyle(STATUS_STYLE_SUCCESS);
        }
    }

    private int compareNatural(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return Comparator.nullsFirst(String::compareToIgnoreCase).compare(s1, s2);
        }

        String[] tokens1 = s1.split("(?<=\\D)(?=\\d)|(?<=\\d)(?=\\D)");
        String[] tokens2 = s2.split("(?<=\\D)(?=\\d)|(?<=\\d)(?=\\D)");

        int minLen = Math.min(tokens1.length, tokens2.length);
        for (int i = 0; i < minLen; i++) {
            int cmp = compareTokenPair(tokens1[i], tokens2[i]);
            if (cmp != 0) {
                return cmp;
            }
        }
        return Integer.compare(tokens1.length, tokens2.length);
    }

    private int compareTokenPair(String p1, String p2) {
        if (p1.matches("\\d+") && p2.matches("\\d+")) {
            return compareNumericTokens(p1, p2);
        }
        return p1.compareToIgnoreCase(p2);
    }

    private int compareNumericTokens(String n1, String n2) {
        String trimmed1 = n1.replaceFirst("^0+", "");
        String trimmed2 = n2.replaceFirst("^0+", "");

        if (trimmed1.length() != trimmed2.length()) {
            return Integer.compare(trimmed1.length(), trimmed2.length());
        }

        int cmp = trimmed1.compareTo(trimmed2);
        if (cmp != 0) {
            return cmp;
        }

        return Integer.compare(n2.length(), n1.length());
    }
}