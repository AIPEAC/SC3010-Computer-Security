/*
 * VULNERABLE CODE
 * File: src/main/java/com/demo/UserService.java
 * Purpose: Database layer — reads user credentials from data/users.yaml using SnakeYAML.
 *          Represents the sensitive data store (PII / credential database) that an attacker
 *          can access after gaining RCE through CVE-2017-5638.
 * Time in attack timeline: Data at rest pre-attack; becomes exfiltration target after
 *                           the attacker achieves remote code execution on May 13, 2017.
 */
package com.demo;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Reads user records from {@code data/users.yaml} on the classpath.
 *
 * Each user record has three fields:
 * <ul>
 *   <li>{@code id}       — UUID string</li>
 *   <li>{@code username} — display name</li>
 *   <li>{@code password} — plaintext password (intentionally insecure for demo)</li>
 * </ul>
 */
public class UserService {

    private static final String USERS_YAML = "/data/users.yaml";

    /**
     * Returns the list of user maps loaded from users.yaml.
     * Each map contains keys: id, username, password.
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, String>> getUsers() {
        Yaml yaml = new Yaml();
        InputStream in = getClass().getResourceAsStream(USERS_YAML);
        if (in == null) {
            return Collections.emptyList();
        }
        Map<String, Object> root = yaml.load(in);
        Object users = root.get("users");
        if (users instanceof List) {
            return (List<Map<String, String>>) users;
        }
        return Collections.emptyList();
    }
}
