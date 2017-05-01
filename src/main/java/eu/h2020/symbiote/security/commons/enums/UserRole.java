package eu.h2020.symbiote.security.commons.enums;

/**
 * Denotes what kind of role a user in symbIoTe ecosystem has
 */
public enum UserRole {
    /**
     * default symbIoTe's data consumer role
     */
    APPLICATION,
    /**
     * symbIoTe-enabled platform's owner account type, used to release administration attributes
     */
    PLATFORM_OWNER,
    /**
     * unitialized value of this enum
     */
    NULL
}
