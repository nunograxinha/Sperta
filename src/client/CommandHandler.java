package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Interactive text-protocol client matching the GUI network service.
 */
public class CommandHandler {

    private final BufferedReader in;
    private final PrintWriter out;
    private final Scanner scanner;
    private final String username;
    private final String keystorePath;
    private final String keystorePassword;

    public CommandHandler(
            BufferedReader in,
            PrintWriter out,
            Scanner scanner,
            String username,
            String keystorePath,
            String keystorePassword) {
        this.in = in;
        this.out = out;
        this.scanner = scanner;
        this.username = username;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
    }

    public void startLoop() {
        printBanner();
        while (scanner.hasNextLine()) {
            System.out.print("sperta> ");
            String line = scanner.nextLine().trim();
            if (line.isEmpty()) {
                continue;
            }
            try {
                processCommand(line);
            } catch (IOException | GeneralSecurityException e) {
                System.err.println("[ERROR] " + e.getMessage());
            }
        }
    }

    private void processCommand(String input) throws IOException, GeneralSecurityException {
        String[] parts = input.split("\\s+");
        String command = parts[0].toUpperCase();

        switch (command) {
            case "HOUSES", "LIST_HOUSES" -> listHouses();
            case "STATUS" -> requireParts(parts, 2, values -> getStatus(values[1], false));
            case "CREATE" -> requireParts(parts, 2, values -> createHouse(values[1]));
            case "ADD" -> requireParts(parts, 4,
                    values -> addAccess(values[1], values[2], values[3]));
            case "RD", "REGISTER_DEVICE" -> requireParts(parts, 3,
                    values -> registerDevice(values[1], values[2]));
            case "EC" -> requireParts(parts, 4,
                    values -> executeCommand(values[1], values[2], values[3]));
            case "RH" -> requireParts(parts, 3,
                    values -> getHistory(values[1], values[2]));
            case "RT" -> requireParts(parts, 2, values -> getStatus(values[1], true));
            case "HELP" -> printBanner();
            case "QUIT", "EXIT" -> {
                return;
            }
            default -> System.out.println("[ERROR] Unknown command. Type HELP for available commands.");
        }
    }

    private void listHouses() throws IOException {
        out.println("LIST_HOUSES");
        System.out.println("[HOUSES]");
        String line;
        while ((line = in.readLine()) != null && !"END_HOUSES".equals(line)) {
            printResponseLine(line);
        }
    }

    private void getStatus(String house, boolean saveReport) throws IOException {
        out.println("GET_STATUS " + house);
        System.out.println("[STATUS] " + house);
            StringBuilder report = new StringBuilder()
                    .append("User: ").append(username).append(", House: ").append(house).append('\n');
            String line;
            while ((line = in.readLine()) != null && !"END_STATUS".equals(line)) {
                String formatted = formatStatusLine(line);
                if (formatted != null) {
                    System.out.println(formatted);
                    report.append(formatted.trim())
                            .append(", ")
                            .append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                            .append('\n');
                }
            }
            if (saveReport) {
                Path output = Paths.get("RT", username + "_" + house + "_status.txt");
                Files.createDirectories(output.getParent());
                Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
                System.out.println("[OK] Report saved to " + output);
            }
    }

    private String formatStatusLine(String line) {
            int separator = line.indexOf(':');
            if (separator <= 0) {
                printResponseLine(line);
                return null;
            }

            String device = line.substring(0, separator).trim();
            String rawValue = line.substring(separator + 1).trim();
            String[] stateParts = rawValue.split("@", 2);
            try {
                int minutes = Integer.parseInt(stateParts[0]);
            String state = minutes == 0
                        ? "OFF"
                        : minutes == 1 ? "ON" : "ON (" + minutes + " min)";
                return device + ": " + state;
            } catch (NumberFormatException e) {
                return device + ": " + rawValue;
            }
    }

    private void createHouse(String house) throws IOException, GeneralSecurityException {
        Map<String, byte[]> keys = ClientCryptoHelper.generateAndWrapSectionKeys(
                username, keystorePath, keystorePassword);
        StringBuilder payload = new StringBuilder();
        for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
            if (payload.length() > 0) {
                payload.append(';');
            }
            payload.append(entry.getKey())
                    .append('=')
                    .append(Base64.getEncoder().encodeToString(entry.getValue()));
        }
        out.println("CREATE_HOUSE " + house + " " + payload);
        printResponse(in.readLine());
    }

    private void registerDevice(String house, String section) throws IOException {
        out.println("REGISTER_DEVICE " + house + " " + section.toUpperCase());
        printResponse(in.readLine());
    }

    private void addAccess(String targetUser, String house, String section)
            throws IOException, GeneralSecurityException {
        String normalizedSection = section.toUpperCase();
        out.println("GET_USER_CERT " + targetUser);
        String certificateLine = in.readLine();
        if (certificateLine == null || certificateLine.startsWith("ERROR")) {
            printResponse(certificateLine);
            return;
        }

        out.println("GET_SECTION_KEYS " + house + " " + normalizedSection);
        String keyLine = in.readLine();
        if (keyLine == null || keyLine.startsWith("ERROR")) {
            printResponse(keyLine);
            return;
        }

        Map<String, byte[]> currentKeys = new HashMap<>();
        currentKeys.put(normalizedSection, Base64.getDecoder().decode(keyLine));
        Map<String, byte[]> rewrapped = ClientCryptoHelper.rewrapSectionKeys(
                currentKeys,
                Base64.getDecoder().decode(certificateLine),
                keystorePath,
                keystorePassword,
                username);
        byte[] wrappedKey = rewrapped.get(normalizedSection);
        if (wrappedKey == null) {
            throw new IOException("Could not re-wrap the section key.");
        }

        out.println("GRANT_ACCESS " + house + " " + targetUser + " "
                + normalizedSection + " " + Base64.getEncoder().encodeToString(wrappedKey));
        printResponse(in.readLine());
    }

    private void executeCommand(String house, String device, String rawValue) throws IOException {
        int value;
        try {
            value = Integer.parseInt(rawValue);
        } catch (NumberFormatException e) {
            throw new IOException("EC duration must be an integer between 0 and 600.");
        }
        if (value < 0 || value > 600) {
            throw new IOException("EC duration must be between 0 and 600.");
        }
        out.println("EXECUTE_COMMAND " + house + " " + device.toUpperCase() + " " + value);
        String response = in.readLine();
        if ("OK".equals(response)) {
            System.out.println("[OK] Command executed.");
        } else {
            printResponse(response);
        }
    }

    private void getHistory(String house, String device) throws IOException {
        out.println("GET_DEVICE_HISTORY " + house + " " + device.toUpperCase());
        Path output = Paths.get("RH", house + "_" + device.toUpperCase() + "_history.csv");
        Files.createDirectories(output.getParent());
        try (var writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null && !"END_HISTORY".equals(line)) {
                if (line.startsWith("ERROR")) {
                    printResponse(line);
                    return;
                }
                writer.write(line);
                writer.newLine();
            }
        }
        System.out.println("[OK] History saved to " + output);
    }

    private void requireParts(String[] parts, int count, CommandAction action)
            throws IOException, GeneralSecurityException {
        if (parts.length < count) {
            throw new IOException("Invalid command. Type HELP for usage.");
        }
        action.run(parts);
    }

    private void printResponse(String response) {
        if (response == null) {
            System.out.println("[ERROR] Server closed the connection.");
        } else {
            printResponseLine(response);
        }
    }

    private void printResponseLine(String response) {
        if (response.startsWith("ERROR")) {
            System.out.println("[ERROR] " + response.substring("ERROR:".length()).trim());
        } else if (response.startsWith("OK")) {
            System.out.println("[OK] " + response);
        } else {
            System.out.println("  " + response);
        }
    }

    private void printBanner() {
        System.out.println("""

                ========================================
                    SPERTA COMMAND-LINE COMMANDS
                ========================================
                CREATE <house>                 Create a house
                ADD <user> <house> <section>   Grant section access
                RD <house> <section>           Register a device (for example M)
                EC <house> <device> <minutes>  Send a command (0-600)
                RT <house>                     Show current house status
                RH <house> <device>            Download device history
                HELP                           Show this help
                EXIT                           Close the client
                ========================================
                """);
    }

    @FunctionalInterface
    private interface CommandAction {
        void run(String[] values) throws IOException, GeneralSecurityException;
    }
}
