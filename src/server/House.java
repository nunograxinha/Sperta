package server;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

/**
 * Domain model representing a Smart House profile in the Sperta system.
 * Handles parsing and serialization according to the file storage specification:
 * <owner>
 * <section>:(<dev1>-<val1>,...)[<user1>,...]
 */

public class House {

    private static final String LINE_SEPARATOR = "\n";
    private final String name;
    private final String owner;
    private final Map<String, Section> sections = new LinkedHashMap<>();

    public House(String name, String owner) {
        this.name = name;
        this.owner = owner;
        // Initialize the mandatory smart home sections
        for (String sec : new String[]{"E", "G", "L", "M", "P", "S"}) {
            sections.put(sec, new Section(sec));
        }
    }

    public String getName() {
        return name;
    }

    public String getOwner() {
        return owner;
    }

    public Map<String, Section> getSections() {
        return Collections.unmodifiableMap(sections);
    }

    public Section getSection(String sectionKey) {
        if (sectionKey == null) {
            return null;
        }
        return sections.get(sectionKey.toUpperCase());
    }

    public boolean isAuthorized(String user, String sectionKey) {
        if (owner.equals(user)) {
            return true;
        }
        Section sec = getSection(sectionKey);
        return sec != null && sec.hasUser(user);
    }

    public String toFileFormat() {
        StringBuilder sb = new StringBuilder();
        sb.append(owner).append(LINE_SEPARATOR);
        for (Section sec : sections.values()) {
            sb.append(sec.toFileFormat()).append(LINE_SEPARATOR);
        }
        return sb.toString();
    }

    public static House fromFileFormat(String houseName, String content) {
        try (Scanner sc = new Scanner(content)) {
            if (!sc.hasNextLine()) {
                return null;
            }
            String owner = sc.nextLine().trim();
            House house = new House(houseName, owner);

            while (sc.hasNextLine()) {
                String line = sc.nextLine().trim();
                parseLine(house, line);
            }
            return house;
        }
    }

    private static void parseLine(House house, String line) {
        if (line.isEmpty() || !line.contains(":")) {
            return;
        }

        int colonIdx = line.indexOf(':');
        String secName = line.substring(0, colonIdx).trim().toUpperCase();
        Section section = house.sections.computeIfAbsent(secName, Section::new);

        parseDevices(section, line);
        parseUsers(section, line);
    }

    private static void parseDevices(Section section, String line) {
        int startParen = line.indexOf('(');
        int endParen = line.lastIndexOf(')');
        if (startParen == -1 || endParen <= startParen) {
            return;
        }

        String devData = line.substring(startParen + 1, endParen).trim();
        if (devData.isEmpty()) {
            return;
        }

        for (String devEntry : devData.split(",")) {
            String[] devParts = devEntry.trim().split("-");
            if (devParts.length == 2) {
                section.setDeviceValue(devParts[0].trim(), devParts[1].trim());
            }
        }
    }

    private static void parseUsers(Section section, String line) {
        int startBracket = line.indexOf('[');
        int endBracket = line.lastIndexOf(']');
        if (startBracket == -1 || endBracket <= startBracket) {
            return;
        }

        String userData = line.substring(startBracket + 1, endBracket).trim();
        if (userData.isEmpty()) {
            return;
        }

        for (String u : userData.split(",")) {
            section.addUser(u.trim());
        }
    }

    public static class Section {
        private final String name;
        private final Map<String, String> devices = new LinkedHashMap<>();
        private final Set<String> authorizedUsers = new LinkedHashSet<>();

        public Section(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public Map<String, String> getDevices() {
            return Collections.unmodifiableMap(devices);
        }

        public Set<String> getAuthorizedUsers() {
            return Collections.unmodifiableSet(authorizedUsers);
        }

        public void addUser(String user) {
            authorizedUsers.add(user);
        }

        public boolean hasUser(String user) {
            return authorizedUsers.contains(user);
        }

        public void setDeviceValue(String deviceId, String value) {
            devices.put(deviceId, value);
        }

        public int getNextDeviceId() {
            int maxId = 0;
            for (String devId : devices.keySet()) {
                if (devId.startsWith(name)) {
                    try {
                        int num = Integer.parseInt(devId.substring(name.length()));
                        if (num > maxId) {
                            maxId = num;
                        }
                    } catch (NumberFormatException ignored) {
                        // Expected when device ID suffix is not a parsable integer
                    }
                }
            }
            return maxId + 1;
        }

        public String toFileFormat() {
            String devData = devices.entrySet().stream()
                    .map(entry -> entry.getKey() + "-" + entry.getValue())
                    .collect(java.util.stream.Collectors.joining(","));

            StringBuilder sb = new StringBuilder();
            sb.append(name)
              .append(":(")
              .append(devData)
              .append(")[")
              .append(String.join(",", authorizedUsers))
              .append("]");
            return sb.toString();
        }
    }
}