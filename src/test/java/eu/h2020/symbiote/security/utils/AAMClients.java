package eu.h2020.symbiote.security.utils;

import feign.Feign;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

/*
 * For easier client creation
 */
public class AAMClients {
    public static FeignRestInterface getJsonClient(String serveraddress) {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignRestInterface.class, serveraddress);
    }

    public static FeignRestInterface getPlaintextClient(String serveraddress) {
        return Feign.builder().decoder(new JacksonDecoder())
                .target(FeignRestInterface.class, serveraddress);
    }
}
