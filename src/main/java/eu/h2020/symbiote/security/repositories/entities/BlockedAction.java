package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.enums.EventType;
import org.springframework.data.annotation.Id;

public class BlockedAction {

    @Id
    private final String username;
    private final EventType eventType;
    private final long timeout;
    private final long duration;


    public BlockedAction(String username, EventType eventType, long timeout, long duration) {
        this.username = username;
        this.eventType = eventType;
        this.timeout = timeout;
        this.duration = duration;
    }

    public String getUsername() {
        return username;
    }

    public long getTimeout() {
        return timeout;
    }

    public long getDuration() {
        return duration;
    }

    public EventType getEventType() {
        return eventType;
    }
}
