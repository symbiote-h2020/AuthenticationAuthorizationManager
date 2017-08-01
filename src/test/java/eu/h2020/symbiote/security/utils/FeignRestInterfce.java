package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/*
 *  Provides services provided by AAMS  (WIP)
 *  @author Dariusz Krajewski (PSNC)
 */

public interface FeignRestInterfce {

    @RequestLine("GET " + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    Response getComponentCertificate();

    @RequestLine("POST " + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE)
    @Headers("Content-Type: application/json")
    Response getClientCertificate(CertificateRequest certificateRequest);

    @RequestLine("POST " + SecurityConstants.AAM_GET_GUEST_TOKEN)
    Response getGuestToken();

    @RequestLine("POST " + SecurityConstants.AAM_GET_HOME_TOKEN)
    @Headers("Content-Type: application/json")
    Response getHomeToken(String loginRequest);


}
