package eu.h2020.symbiote.commons;

/**
 * Created by Mikołaj Dobski on 03.04.2017.
 */
public enum Role {
    /**
     * specifies platform owner account (administrative user)
     */
    PLATFORM_OWNER,
    /**
     * specifies simple data consumer account (ordinary user)
     */
    APPLICATION,
    /** uninitialised value of this enum */
    NULL;
}
