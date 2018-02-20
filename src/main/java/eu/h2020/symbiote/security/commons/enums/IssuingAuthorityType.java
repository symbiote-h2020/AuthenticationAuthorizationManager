package eu.h2020.symbiote.security.commons.enums;

/**
 * Used to define the {eu.h2020.symbiote.security.AuthenticationAuthorizationManager} deployment type:
 * CoreAAM,
 * ServiceAAM
 *
 * @author Mikołaj Dobski (PSNC)
 */
public enum IssuingAuthorityType {
    /**
     * Core AAM
     */
    CORE,
    /**
     * Platform AAM
     */
    PLATFORM,
    /**
     * SMART SPACES AAM
     */
    SSP,

    /**
     * uninitialised value of this enum, useful for TestAAM
     */
    NULL
}
