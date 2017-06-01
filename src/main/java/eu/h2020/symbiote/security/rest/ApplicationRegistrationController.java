package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.VirtualFile;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.interfaces.IRegistration;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.services.UserRegistrationService;
import eu.h2020.symbiote.security.services.ZipService;
import net.lingala.zip4j.exception.ZipException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app registration
 * service in Cloud AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see TokenService
 */
@RestController
public class ApplicationRegistrationController implements IRegistration {

    private static Log log = LogFactory.getLog(ApplicationRegistrationController.class);
    private final UserRegistrationService registrationService;
    private final ZipService zipService;

    @Autowired
    public ApplicationRegistrationController(UserRegistrationService registrationService, ZipService zipService) {
        this.registrationService = registrationService;
        this.zipService = zipService;
    }
    public ResponseEntity<?> register(@RequestParam Map<String, String> requestMap, HttpServletResponse response)
            throws AAMException, IOException, ZipException {
        UserRegistrationRequest request = new UserRegistrationRequest();
        // TODO R3 incorporate federated Id (and possibly recovery e-mail)
        request.setUserDetails(new UserDetails(new Credentials(requestMap.get("username"), requestMap.get("password")
        ), "R3-feature", "not-applicable", UserRole.APPLICATION));
        UserRegistrationResponse regResponse = registrationService.register(request);
        String certificate = regResponse.getUserCertificate().toString();
        String privateKey = regResponse.getUserPrivateKey();
        InputStream certInputStream = new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8));
        InputStream pvKeyInputStream = new ByteArrayInputStream(privateKey.getBytes(StandardCharsets.UTF_8));
        VirtualFile vCert = new VirtualFile(certInputStream, "certificate.pem");
        VirtualFile vPvKey = new VirtualFile(pvKeyInputStream, "private_key.pem");
        response.setContentType("Content-type: text/zip");
        response.setHeader("Content-Disposition", "attachment; filename=app.zip");
        ServletOutputStream out = response.getOutputStream();
        List virtualFiles = new ArrayList();
        virtualFiles.add(vCert);
        virtualFiles.add(vPvKey);
        zipService.zip(virtualFiles, out);
        return new ResponseEntity<HttpServletResponse>(response, HttpStatus.OK);
    }

    public ResponseEntity<?> register(@RequestBody UserRegistrationRequest request) {
        try {
            UserRegistrationResponse response = registrationService.authRegister(request);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (AAMException e) {
            log.error(e);
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());
        }
    }

    public ResponseEntity<?> unregister(@RequestBody UserRegistrationRequest request) {
        try {
            registrationService.authUnregister(request);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (AAMException e) {
            log.error(e);
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}