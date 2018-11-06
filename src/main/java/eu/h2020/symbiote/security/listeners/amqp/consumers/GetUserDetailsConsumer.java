package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * RabbitMQ Consumer implementation used for providing requested user's details
 * <p>
 */
@Profile({"core", "platform"})
@Component
public class GetUserDetailsConsumer {

    private static Log log = LogFactory.getLog(GetUserDetailsConsumer.class);
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.get.user.details}",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    arguments = {@Argument(
                            name = "x-message-ttl",
                            value = "${rabbit.message-ttl}",
                            type = "java.lang.Integer")},
                    exclusive = "false"),
            exchange = @Exchange(
                    value = "${rabbit.exchange.aam.name}",
                    ignoreDeclarationExceptions = "true",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "${rabbit.exchange.aam.type}"),
            key = "${rabbit.routingKey.get.user.details}"))
    public byte[] getUserDetails(byte[] body) {
        try {
            log.debug("[x] Received User Details Request");
            byte[] response;
            String message;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()).toJson().getBytes();
                return response;
            }


            try {
                UserManagementRequest userManagementRequest = om.readValue(message, UserManagementRequest.class);
                Credentials administratorCredentials = userManagementRequest.getAdministratorCredentials();
                Credentials userCredentials = userManagementRequest.getUserCredentials();
                // TODO harden Credentials so that NULLs are forbidden

                // check if we received required administrator credentials and user credentials for API auth
                if (administratorCredentials == null
                        || administratorCredentials.getUsername() == null
                        || administratorCredentials.getPassword() == null
                        || userCredentials == null
                        || userCredentials.getUsername() == null
                        || userCredentials.getPassword() == null)
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIALS);
                // and if the admin credentials match those from properties
                if (!administratorCredentials.getUsername().equals(adminUsername)
                        || !administratorCredentials.getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.FORBIDDEN);
                //  begin checking requested user's credentials
                String username = userManagementRequest.getUserCredentials().getUsername();
                //  Check if user exists in database
                if (!userRepository.exists(username)) {
                    //  If not then return appropriate message
                    return om.writeValueAsString(new UserDetailsResponse(HttpStatus.BAD_REQUEST, new UserDetails())).getBytes();
                }
                //  User IS in database
                User foundUser = userRepository.findOne(username);
                UserDetails foundUserDetails = new UserDetails(new Credentials(foundUser.getUsername(), ""),
                        foundUser.getRecoveryMail(),
                        foundUser.getRole(),
                        foundUser.getStatus(),
                        foundUser.getAttributes(),
                        foundUser.getClientCertificates(),
                        foundUser.hasGrantedServiceConsent(),
                        foundUser.hasGrantedAnalyticsAndResearchConsent());

                switch (userManagementRequest.getOperationType()) {
                    case READ: // ordinary check fetching the user details by the user
                        //  Checking User's credentials
                        if (!passwordEncoder.matches(userCredentials.getPassword(), foundUser.getPasswordEncrypted())) {
                            //  If wrong password was provided return message with UNAUTHORIZED status
                            return om.writeValueAsString(new UserDetailsResponse(HttpStatus.UNAUTHORIZED, new UserDetails())).getBytes();
                        }
                        // inactive accounts should be blocked
                        if (foundUser.getStatus() != AccountStatus.ACTIVE)
                            return om.writeValueAsString(new UserDetailsResponse(
                                    HttpStatus.FORBIDDEN,
                                    foundUserDetails
                            )).getBytes();
                    case FORCE_READ: // used by the administrator to fetch user details
                        return om.writeValueAsString(new UserDetailsResponse(
                                HttpStatus.OK,
                                foundUserDetails
                        )).getBytes();
                    default:
                        return om.writeValueAsString(new UserDetailsResponse(HttpStatus.BAD_REQUEST, null)).getBytes();
                }
            } catch (InvalidArgumentsException e) {
                log.error(e);
                // Missing Admin or User credentials
                response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.UNAUTHORIZED, null)).getBytes();
                return response;
            } catch (UserManagementException e) {
                log.error(e);
                // Incorrect Admin login / password
                response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.FORBIDDEN, null)).getBytes();
                return response;
            } catch (IOException e) {
                log.error(e);
                response = om.writeValueAsString(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value())).getBytes();
                return response;
            }
        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}