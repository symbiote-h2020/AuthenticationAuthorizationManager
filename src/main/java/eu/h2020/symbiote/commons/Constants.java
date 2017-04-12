package eu.h2020.symbiote.commons;

/**
 * Recipient class used to collect all the constant values used throughout Cloud AAM code.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class Constants {

    public static final String ERROR_WRONG_TOKEN = "ERR_WRONG_TOKEN";

    public static final String TOKEN_HEADER_NAME = "X-Auth-Token";
    
    public static final long serialVersionUID = 7526472295622776147L;

    public static final int JWTPartsCount = 3; //Header, body and signature

    public static final String ERR_TOKEN_EXPIRED = "TOKEN_EXPIRED";
    public static final String ERR_TOKEN_WRONG_ISSUER = "TOKEN_WRONG_ISSUER";
}
