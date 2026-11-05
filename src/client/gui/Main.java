package client.gui;

import javafx.application.Application;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.File;
import java.io.InputStream;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Sperta IoT Client");

        setAppIcon(primaryStage);

        SpertaNetworkService networkService = new SpertaNetworkService();
        LoginView loginView = new LoginView(primaryStage, networkService);

        primaryStage.setScene(loginView.createScene());

        primaryStage.setOnCloseRequest(e -> {
            networkService.disconnect();
            System.exit(0);
        });

        primaryStage.show();
    }

    private void setAppIcon(Stage stage) {
        try {
            InputStream is = getClass().getResourceAsStream("/client/gui/icon.png");
            if (is == null) {
                is = getClass().getResourceAsStream("icon.png");
            }
            if (is != null) {
                stage.getIcons().add(new Image(is));
            } else {
                File localIcon = new File("src/client/gui/icon.png");
                if (localIcon.exists()) {
                    stage.getIcons().add(new Image(localIcon.toURI().toString()));
                }
            }
        } catch (Exception ignored) {
            // Keep the default icon if loading fails
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}