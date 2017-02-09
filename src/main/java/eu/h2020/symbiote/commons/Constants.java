package eu.h2020.symbiote.commons;


/**
 * Recipient class used to collect all the constant values used throughout Cloud AAM code.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class Constants {

    public static final String ERROR_WRONG_TOKEN = "ERR_WRONG_TOKEN";

    public static final long serialVersionUID = 7526472295622776147L;

    // AMQP message queues related constants (queues and routing key names)
    public final static String PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE = "symbIoTe-platformAAM-registrationHandler-login_request";
    public final static String PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_ROUTING_KEY = "symbIoTe.platformAAM.registrationHandler.login_request";
    public final static String REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE = "symbIoTe-registrationHandler-platformAAM-login_reply";
    public final static String REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_ROUTING_KEY = "symbIoTe.registrationHandler.platformAAM.login_reply";
    
    public final static String PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE = "symbIoTe-platformAAM-monitoring-login_request";
    public final static String PLATFORM_AAM_MONITORING_LOGIN_REQUEST_ROUTING_KEY = "symbIoTe.platformAAM.monitoring.login_request";
    public final static String MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE = "symbIoTe-monitoring-platformAAM-login_reply";
    public final static String MONITORING_PLATFORM_AAM_LOGIN_REPLY_ROUTING_KEY = "symbIoTe.monitoring.platformAAM.login_reply";
 
    public final static String PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_ROUTING_KEY = "symbIoTe.platformAAM.platformRAP.check_token_revocation_request";
    public final static String PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE = "symbIoTe-platformAAM-platformRAP-check_token_revocation_request";
    public final static String PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE = "symbIoTe-platformRAP-platformAAM-check_token_revocation_reply";
    public final static String PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_ROUTING_KEY = "symbIoTe.platformRAP.platformAAM.check_token_revocation_reply";
}
