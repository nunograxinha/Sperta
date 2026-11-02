package server;

import java.util.*;

/**
 * Domain model representing a Smart House profile in the Sperta system.
 * Handles parsing and serialization to the required file storage specification:
 * <owner>
 * <section>:(<dev1>-<val1>,...)[<user1>,...]
 */
public class House {
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
        return sections;
    }

    public Section getSection(String sectionKey) {
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
        sb.append(owner).append("\n");
        for (Section sec : sections.values()) {
            sb.append(sec.toFileFormat()).append("\n");
        }
        return sb.toString();
    }

    public static House fromFileFormat(String houseName, String content) {
        Scanner sc = new Scanner(content);
        if (!sc.hasNextLine()) {
            return null;
        }
        String owner = sc.nextLine().trim();
        House house = new House(houseName, owner);

        while (sc.hasNextLine()) {
            String line = sc.nextLine().trim();
            if (line.isEmpty() || !line.contains(":")) {
                continue;
            }

            int colonIdx = line.indexOf(':');
            String secName = line.substring(0, colonIdx).trim().toUpperCase();
            Section section = house.getSection(secName);
            if (section == null) {
                section = new Section(secName);
                house.sections.put(secName, section);
            }

            int startParen = line.indexOf('(');
            int endParen = line.lastIndexOf(')');
            if (startParen != -1 && endParen > startParen) {
                String devData = line.substring(startParen + 1, endParen).trim();
                if (!devData.isEmpty()) {
                    for (String devEntry : devData.split(",")) {
                        String[] devParts = devEntry.trim().split("-");
                        if (devParts.length == 2) {
                            section.setDeviceValue(devParts[0].trim(), devParts[1].trim());
                        }
                    }
                }
            }

            int startBracket = line.indexOf('[');
            int endBracket = line.lastIndexOf(']');
            if (startBracket != -1 && endBracket > startBracket) {
                String userData = line.substring(startBracket + 1, endBracket).trim();
                if (!userData.isEmpty()) {
                    for (String u : userData.split(",")) {
                        section.addUser(u.trim());
                    }
                }
            }
        }
        return house;
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
            return devices;
        }

        public Set<String> getAuthorizedUsers() {
            return authorizedUsers;
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
                    } catch (NumberFormatException ignored) {}
                }
            }
            return maxId + 1;
        }

        public String toFileFormat() {
            StringBuilder sb = new StringBuilder();
            sb.append(name).append(":(");
            List<String> devList = new ArrayList<>();
            for (Map.Entry<String, String> entry : devices.entrySet()) {
                devList.add(entry.getKey() + "-" + entry.getValue());
            }
            sb.append(String.join(",", devList));
            sb.append(")[");
            sb.append(String.join(",", authorizedUsers));
            sb.append("]");
            return sb.toString();
        }
    }
}