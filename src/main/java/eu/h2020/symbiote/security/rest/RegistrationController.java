package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.CustomAAMException;
import eu.h2020.symbiote.security.commons.VirtualFile;
import eu.h2020.symbiote.security.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.security.commons.json.PlainCredentials;
import eu.h2020.symbiote.security.commons.json.RegistrationRequest;
import eu.h2020.symbiote.security.commons.json.RegistrationResponse;
import eu.h2020.symbiote.security.services.ApplicationRegistrationService;
import eu.h2020.symbiote.security.services.LoginService;
import eu.h2020.symbiote.security.services.ZipService;
import net.lingala.zip4j.exception.ZipException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app registration
 * service in Cloud AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see LoginService
 */
@RestController
public class RegistrationController {

    private final ApplicationRegistrationService registrationService;
    private final ZipService zipService;

    @Autowired
    public RegistrationController(ApplicationRegistrationService registrationService, ZipService zipService) {
        this.registrationService = registrationService;
        this.zipService = zipService;
    }

    @PreAuthorize("isAuthenticated()")
    @RequestMapping(value = "/registration", method = RequestMethod.POST)
    public ResponseEntity<?> register(@RequestParam Map<String, String> requestMap, HttpServletResponse response)
        throws CustomAAMException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException,
        OperatorCreationException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException,
        IOException, ZipException {
        PlainCredentials user = new PlainCredentials(requestMap.get("username"), requestMap.get("password"));
        RegistrationResponse regResponse = registrationService.register(user);
        String certificate = regResponse.getPemCertificate();
        String privateKey = regResponse.getPemPrivateKey();
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

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> register(@RequestBody RegistrationRequest request) throws CertificateException,
        UnrecoverableKeyException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException,
        NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        try {
            RegistrationResponse response = registrationService.authRegister(request);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                .getStatusCode().ordinal()), e.getStatusCode());
        }
    }

    @RequestMapping(value = "/unregister", method = RequestMethod.POST)
    public ResponseEntity<?> unregister(@RequestBody RegistrationRequest request) throws CertificateException,
        UnrecoverableKeyException, NoSuchAlgorithmException, OperatorCreationException, KeyStoreException,
        NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        try {
            registrationService.authUnregister(request);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                .getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}