package eu.h2020.symbiote.security.commons.enums;

import eu.h2020.symbiote.security.commons.jwt.JWTClaims;

/**
 * Used to define the {@link eu.h2020.symbiote.security.AuthenticationAuthorizationManager} deployment type:
 * CoreAAM,
 * PlatformAAM
 * or NullAAM (for tests)
 * <p>
 * Propagates as JWT token Type - {@link JWTClaims#getTtyp()}
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
