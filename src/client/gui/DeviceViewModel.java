package client.gui;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

/**
 * View model representing an individual smart home device in the JavaFX table.
 * Supports end-to-end payload parsing ("<value>@<timestamp>") and dynamic real-time countdown.
 */
public class DeviceViewModel {

    private final StringProperty deviceId;
    private final StringProperty section;
    private final StringProperty value;

    private int initialMinutes;
    private long lastCommandTimestamp;

    /**
     * Primary constructor accepting device ID, section, and raw decrypted value string.
     *
     * @param deviceId Unique identifier of the device (e.g., "M1", "E2").
     * @param section House section identifier.
     * @param rawDecryptedValue Decrypted string from the server (either "<minutes>" or "<minutes>@<epochMs>").
     */
    public DeviceViewModel(String deviceId, String section, String rawDecryptedValue) {
        String safeDeviceId = (deviceId == null) ? "" : deviceId.trim();
        String safeSection = (section == null) ? "" : section.trim();

        this.deviceId = new SimpleStringProperty(safeDeviceId);
        this.section = new SimpleStringProperty(safeSection);

        int parsedMinutes = 0;
        long commandTimestamp = System.currentTimeMillis();

        if (rawDecryptedValue != null && !rawDecryptedValue.isBlank()) {
            String val = rawDecryptedValue.trim();
            if (val.contains("@")) {
                String[] parts = val.split("@");
                try {
                    parsedMinutes = Integer.parseInt(parts[0].trim());
                    commandTimestamp = Long.parseLong(parts[1].trim());
                } catch (NumberFormatException ignored) {
                    parsedMinutes = 0;
                }
            } else {
                try {
                    parsedMinutes = Integer.parseInt(val);
                } catch (NumberFormatException ignored) {
                    parsedMinutes = 0;
                }
            }
        }

        this.initialMinutes = parsedMinutes;
        this.lastCommandTimestamp = commandTimestamp;
        this.value = new SimpleStringProperty(calculateRealTimeState(this.initialMinutes, this.lastCommandTimestamp));
    }

    /**
     * Overloaded constructor accepting device ID and raw decrypted value.
     * Automatically extracts the section character from the device ID prefix.
     *
     * @param deviceId Unique identifier of the device.
     * @param rawDecryptedValue Decrypted command value or state string.
     */
    public DeviceViewModel(String deviceId, String rawDecryptedValue) {
        this(
            deviceId,
            (deviceId != null && !deviceId.isBlank()) ? String.valueOf(deviceId.trim().toUpperCase().charAt(0)) : "",
            rawDecryptedValue
        );
    }

    /**
     * Updates the target timer and resets the command timestamp when an EC command is executed.
     *
     * @param minutes The new target duration in minutes (0 = OFF, 1 = permanent ON, > 1 = countdown).
     */
    public void updateTimer(int minutes) {
        this.initialMinutes = minutes;
        this.lastCommandTimestamp = System.currentTimeMillis();
        updateDisplayState();
    }

    /**
     * Recalculates the displayed state based on elapsed system time.
     */
    public void updateDisplayState() {
        setValue(calculateRealTimeState(this.initialMinutes, this.lastCommandTimestamp));
    }

    /**
     * Calculates the real-time display state:
     * - <= 0: "OFF"
     * - 1: "ON" (permanent switch mode, never decrements)
     * - > 1: "ON (X min)", decrementing minute by minute down to "ON (1 min)" and then "OFF".
     *
     * @param initialValue The original timer duration set by the user in minutes.
     * @param commandTimestampEpochMs The timestamp (in epoch milliseconds) when the command was issued.
     * @return Formatted state string.
     */
    public static String calculateRealTimeState(int initialValue, long commandTimestampEpochMs) {
        if (initialValue <= 0) {
            return "OFF";
        }

        if (initialValue == 1) {
            return "ON";
        }

        long elapsedMinutes = (System.currentTimeMillis() - commandTimestampEpochMs) / (60 * 1000);
        long remainingMinutes = initialValue - elapsedMinutes;

        if (remainingMinutes <= 0) {
            return "OFF";
        }

        return "ON (" + remainingMinutes + " min)";
    }

    public int getInitialMinutes() {
        return initialMinutes;
    }

    public void setInitialMinutes(int initialMinutes) {
        this.initialMinutes = initialMinutes;
    }

    public long getLastCommandTimestamp() {
        return lastCommandTimestamp;
    }

    public void setLastCommandTimestamp(long lastCommandTimestamp) {
        this.lastCommandTimestamp = lastCommandTimestamp;
    }

    public String getDeviceId() {
        return deviceId.get();
    }

    public StringProperty deviceIdProperty() {
        return deviceId;
    }

    public String getSection() {
        return section.get();
    }

    public StringProperty sectionProperty() {
        return section;
    }

    public String getValue() {
        return value.get();
    }

    public void setValue(String value) {
        this.value.set(value);
    }

    public StringProperty valueProperty() {
        return value;
    }
}