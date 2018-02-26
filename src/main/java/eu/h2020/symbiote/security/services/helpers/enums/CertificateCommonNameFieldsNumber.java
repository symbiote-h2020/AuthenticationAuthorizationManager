package eu.h2020.symbiote.security.services.helpers.enums;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

public enum CertificateCommonNameFieldsNumber {

    /**
     * Platform or smart space
     */
    SERVICE,
    COMPONENT,
    CLIENT;

    public static CertificateCommonNameFieldsNumber getEnumFromInt(int parts) throws
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
