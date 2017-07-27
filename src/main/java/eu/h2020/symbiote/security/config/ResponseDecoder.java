package eu.h2020.symbiote.security.config;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import feign.FeignException;
import feign.Response;
import feign.codec.Decoder;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * Custom Decoder used to convert from feign Response to JaxRS Response
 *
 * @author Dariusz Krajewski (PSNC)
 */
public final class ResponseDecoder implements Decoder{

    @Override
    public Object decode(Response response, Type type) throws IOException, FeignException {
        if(type == javax.ws.rs.core.Response.class){
            return javax.ws.rs.core.Response
                    .status(response.status())
                    .header(SecurityConstants.TOKEN_HEADER_NAME, response.headers().get("x-auth-token").toArray()[0])
                    .build();
        }
        return null;
    }
}
