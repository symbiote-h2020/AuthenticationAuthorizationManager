package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Exposes services allowing SymbIoTe actors (users) to acquire authorization tokens
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 * @author Daniele Caldarola (CNIT)
 * @author Pietro Tedeschi (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Api(value = "/docs/gettokenservice", description = "Exposes services responsible for providing Tokens")
public interface IGetToken {
    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    @ApiOperation(value = "Issues a Guest Token")
    @PostMapping(SecurityConstants.AAM_GET_GUEST_TOKEN)
    ResponseEntity<String> getGuestToken();

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    @ApiOperation(value = "Issues a Home Token")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "Home AAM", value = "AAM the user has account in", required = true, dataType = "body"),
            @ApiImplicitParam(name = "Username", value = "Username of logging user", required = true, dataType = "body"),
            @ApiImplicitParam(name = "Client's ID", value = "ID of logging user", required = true, dataType = "body"),
            @ApiImplicitParam(name = "Certificate", value = "Client's Certificate", required = true, dataType = "body"),
            @ApiImplicitParam(name = "PrivateKey", value = "Key matching the public key in certificate", required = true, dataType = "body"),
    })
    @PostMapping(value = SecurityConstants.AAM_GET_HOME_TOKEN)
    ResponseEntity<String> getHomeToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String loginRequest);

    /**
     * @param remoteHomeToken   that an actor wants to exchange in this AAM for a FOREIGN token
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    @ApiOperation(value = "Issues a Foreign Token")

    @PostMapping(value = SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    ResponseEntity<String> getForeignToken(
            @ApiParam(value = "Token that will be exchanged for Foreign Token", required = true) @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String remoteHomeToken,
            @ApiParam(value = "in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios", required = false) @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @ApiParam(value = "in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios", required = false) @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String aamCertificate);
}
