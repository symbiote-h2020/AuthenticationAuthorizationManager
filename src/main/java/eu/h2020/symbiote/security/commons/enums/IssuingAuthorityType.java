package eu.h2020.symbiote.security.commons.enums;

/**
 * Used to define the {eu.h2020.symbiote.security.AuthenticationAuthorizationManager} deployment type:
 * CoreAAM,
 * PlatformAAM
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
     * uninitialised value of this enum, useful for TestAAM
     */
    NULL
}
