package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import feign.RequestLine;
import feign.Response;

/*
 *  Provides services provided by AAMS  (WIP)
 *  @author Dariusz Krajewski (PSNC)
 */

public interface FeignRestInterfce {
    //  DONE
    @RequestLine("GET " + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    Response getComponentCertificate();

}
