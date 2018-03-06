package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
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
public class GetUserDetailsConsumerService {

    private static Log log = LogFactory.getLog(GetUserDetailsConsumerService.class);
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
                log.info(message);
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()).toJson().getBytes();
                return response;
            }


            try {
                UserManagementRequest userManagementRequest = om.readValue(message, UserManagementRequest.class);
                Credentials administratorCredentials = userManagementRequest.getAdministratorCredentials();

                // check if we received required administrator credentials and user credentials for API auth
                if (administratorCredentials == null || userManagementRequest.getUserCredentials() == null)
                    throw new InvalidArgumentsException();
                // and if the admin credentials match those from properties
                if (!administratorCredentials.getUsername().equals(adminUsername)
                        || !administratorCredentials.getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.FORBIDDEN);
                //  begin checking requested user's credentials
                UserDetailsResponse userDetails;
                String username = userManagementRequest.getUserCredentials().getUsername();
                //  Check if user exists in database
                if (!userRepository.exists(username)) {
                    //  If not then return appropriate message
                    userDetails = new UserDetailsResponse(HttpStatus.BAD_REQUEST, new UserDetails());
                } else {   //  User IS in database
                    User foundUser = userRepository.findOne(username);
                    //  Checking User's credentials
                    if (passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), foundUser.getPasswordEncrypted())) {
                        userDetails = new UserDetailsResponse(
                                HttpStatus.OK, new UserDetails(new Credentials(foundUser.getUsername(), ""), foundUser.getRecoveryMail(),
                                foundUser.getRole(), foundUser.getAttributes(), foundUser.getClientCertificates())
                        );
                    } else
                        //  If wrong password was provided return message with UNAUTHORIZED status
                        userDetails = new UserDetailsResponse(HttpStatus.UNAUTHORIZED, new UserDetails());
                }
                response = om.writeValueAsString(userDetails).getBytes();
            } catch (InvalidArgumentsException e) {
                log.error(e);
                // Missing Admin or User credentials
                response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.UNAUTHORIZED, new UserDetails())).getBytes();
                return response;
            } catch (UserManagementException e) {
                log.error(e);
                // Incorrect Admin login / password
                response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.FORBIDDEN, new UserDetails())).getBytes();
                return response;
            } catch (IOException e) {
                log.error(e);
                response = om.writeValueAsString(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value())).getBytes();
                return response;
            }
            return response;
        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}