package client.gui;

import java.io.File;
import java.io.InputStream;

import javafx.application.Application;
import javafx.stage.Stage;

public class SpertaApp extends Application {

    private final SpertaNetworkService networkService = new SpertaNetworkService();

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Sperta Smart Home - Dashboard");
        setAppIcon(primaryStage);
        LoginView loginView = new LoginView(primaryStage, networkService);
        primaryStage.setScene(loginView.createScene());
        primaryStage.setOnCloseRequest(e -> networkService.disconnect());
        primaryStage.show();
    }

    private void setAppIcon(Stage stage) {
        try {
            InputStream iconStream = getClass().getResourceAsStream("/client/gui/icon.png");
            if (iconStream == null) {
                iconStream = getClass().getResourceAsStream("icon.png");
            }

            if (iconStream != null) {
                stage.getIcons().add(new javafx.scene.image.Image(iconStream));
            } else {
                File iconFile = new File("src/client/gui/icon.png");
                if (iconFile.exists()) {
                    stage.getIcons().add(new javafx.scene.image.Image(iconFile.toURI().toString()));
        }
            }
        } catch (Exception e) {
            // Keep the default icon if loading fails
       }
    }

    public static void main(String[] args) {
        launch(args);
    }
}