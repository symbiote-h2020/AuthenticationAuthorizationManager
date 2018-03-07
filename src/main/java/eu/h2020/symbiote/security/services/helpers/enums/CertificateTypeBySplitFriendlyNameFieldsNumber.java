package eu.h2020.symbiote.security.services.helpers.enums;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

public enum CertificateTypeBySplitFriendlyNameFieldsNumber {

    /**
     * Platform or smart space
     */
    SERVICE,
    /**
     * Component or client
     */
    COMPONENT_OR_CLIENT;

    public static CertificateTypeBySplitFriendlyNameFieldsNumber fromInt(int parts) throws
            InvalidArgumentsException {
        switch (parts) {
            case 1:
                return SERVICE;
            case 2:
                return COMPONENT_OR_CLIENT;
            default:
                throw new InvalidArgumentsException("Wrong number of fields.");
        }
    }
}
