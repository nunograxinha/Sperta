package server;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class SmartDevice {

    private final String deviceId;
    private final String section;
    private final StorageDAO storageDAO;
    private final String houseName;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private ScheduledFuture<?> autoOffTask;
    private int currentState = 0;

    public SmartDevice(String houseName, String deviceId, String section, StorageDAO storageDAO) {
        this.houseName = houseName;
        this.deviceId = deviceId;
        this.section = section;
        this.storageDAO = storageDAO;
    }

    public synchronized void applyCommand(int minutes) {
        if (autoOffTask != null && !autoOffTask.isDone()) {
            autoOffTask.cancel(true);
        }

        this.currentState = minutes;

        if (minutes <= 0) {
            turnOff();
            return;
        }

        if (minutes > 1) {
            // Schedule autonomous shut-off after specified duration
            this.autoOffTask = scheduler.schedule(() -> {
                synchronized (SmartDevice.this) {
                    turnOff();
                    // Append '0' status to the device log
                    logTransitionToZero();
                }
            }, minutes, TimeUnit.MINUTES);
        }
    }

    private void turnOff() {
        this.currentState = 0;
    }

    private void logTransitionToZero() {
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        // Writes "deviceId,0,timestamp" to the respective CSV log file
        storageDAO.logDeviceEvent(houseName, section, deviceId, 0, timestamp);
    }

    public void shutdown() {
        scheduler.shutdownNow();
    }
}