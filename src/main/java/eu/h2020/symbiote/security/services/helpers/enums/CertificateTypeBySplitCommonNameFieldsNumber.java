package eu.h2020.symbiote.security.services.helpers.enums;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

public enum CertificateTypeBySplitCommonNameFieldsNumber {

    /**
     * Platform or smart space
     */
    SERVICE,
    /**
     * service component
     */
    COMPONENT,
    /**
     * ordinary client
     */
    CLIENT;

    public static CertificateTypeBySplitCommonNameFieldsNumber fromInt(int parts) throws
            InvalidArgumentsException {
        switch (parts) {
            case 1:
                return SERVICE;
            case 2:
                return COMPONENT;
            case 3:
                return CLIENT;
            default:
                throw new InvalidArgumentsException("Wrong number of fields.");
        }
    }
}
