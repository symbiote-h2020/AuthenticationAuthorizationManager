package eu.h2020.symbiote.security.commons.jwt.attributes;

/**
 * contains collection of symbIoTe related JWT attributes which might appear in core tokens.
 */
public enum CoreAttributes {
    ROLE("Role"),
    OWNED_PLATFORM("OwnedPlatform");

    private final String value;
    CoreAttributes(final String value) {
        this.value = value;
    }

    /* (non-Javadoc)
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return value;
    }

}
