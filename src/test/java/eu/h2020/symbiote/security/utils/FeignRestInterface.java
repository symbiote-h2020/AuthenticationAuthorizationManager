package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;

/*
 *  Access to services provided by AAMS  (WIP)
 *  @author Dariusz Krajewski (PSNC)
 */

public interface FeignRestInterface {

    @RequestLine("GET " + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    @Headers("Content-Type: application/json")
    AvailableAAMsCollection getAvailableAAMs();

    @RequestLine("GET " + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    Response getComponentCertificate();

    @RequestLine("POST " + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE)
    @Headers("Content-Type: application/json")
    Response getClientCertificate(CertificateRequest certificateRequest);

    @RequestLine("POST " + SecurityConstants.AAM_GET_GUEST_TOKEN)
    Response getGuestToken();

    @RequestLine("POST " + SecurityConstants.AAM_GET_HOME_TOKEN)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.TOKEN_HEADER_NAME + ": " + "{token}"})
    Response getHomeToken(@Param("token") String loginRequest);

    @RequestLine("POST " + SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CERTIFICATE_HEADER_NAME + ": {certificate}",
            "Accept: application/json"})
    Response getForeignToken(@Param("token") String homeToken,
                             @Param("certificate") String certificate);

    @RequestLine("POST " + SecurityConstants.AAM_VALIDATE)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CERTIFICATE_HEADER_NAME + ": {certificate}",
            "Accept: application/json"})
    ValidationStatus validate(@Param("token") String token,
                              @Param("certificate") String certificate);
}