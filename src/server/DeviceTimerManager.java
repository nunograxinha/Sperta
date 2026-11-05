package server;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages countdown timers for IoT devices on the server side, ensuring
 * that once a timed command expires, a state transition to 0 is logged automatically.
 */
public class DeviceTimerManager {

    private static final Logger LOGGER = Logger.getLogger(DeviceTimerManager.class.getName());
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private final Map<String, ScheduledFuture<?>> activeTimers = new ConcurrentHashMap<>();
    private final DeviceUpdateCallback callback;

    @FunctionalInterface
    public interface DeviceUpdateCallback {
        void onDeviceExpired(String houseName, String section, String deviceId, int newValue, String timestamp);
    }

    public DeviceTimerManager(DeviceUpdateCallback callback) {
        this.callback = callback;
    }

    /**
     * Schedules auto-shutoff when a timed command (> 1 minute) is registered.
     */
    public synchronized void scheduleDeviceTimer(String houseName, String section, String deviceId, int minutes) {
        String timerKey = houseName + ":" + deviceId;

        // Cancel existing pending countdown for this device if a new command arrives
        ScheduledFuture<?> existingTask = activeTimers.remove(timerKey);
        if (existingTask != null && !existingTask.isDone()) {
            existingTask.cancel(false);
        }

        // Only positive countdown durations (> 1) require scheduling auto-off
        if (minutes <= 1) {
            return;
        }

        ScheduledFuture<?> task = scheduler.schedule(() -> {
            try {
                String timestamp = LocalDateTime.now(ZoneId.systemDefault()).format(TIMESTAMP_FORMATTER);
                LOGGER.info(() -> "Timer expired for device " + deviceId + " in house " + houseName + ". Logging state 0.");
                if (callback != null) {
                    callback.onDeviceExpired(houseName, section, deviceId, 0, timestamp);
                }
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, ex, () -> "Error executing auto-off callback for device: " + deviceId);
            } finally {
                activeTimers.remove(timerKey);
            }
        }, minutes, TimeUnit.MINUTES);

        activeTimers.put(timerKey, task);
    }

    public void shutdown() {
        scheduler.shutdownNow();
    }
}