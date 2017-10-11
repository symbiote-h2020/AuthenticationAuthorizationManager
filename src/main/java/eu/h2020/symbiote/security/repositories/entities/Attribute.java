package eu.h2020.symbiote.security.repositories.entities;

import org.springframework.data.annotation.Id;

public class Attribute {
    @Id
    private final String key;
    private final String value;

    public Attribute(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }
    public String getValue() {
        return value;
    }
}
