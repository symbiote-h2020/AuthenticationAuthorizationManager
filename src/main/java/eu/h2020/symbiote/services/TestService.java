package eu.h2020.symbiote.services;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;



@Service
public class TestService {

	private static Log log = LogFactory.getLog(TestService.class);
	
    @Autowired
    private RabbitTemplate rabbitTemplate;

    public void testLogin(LoginRequest user) throws MissingArgumentsException,WrongCredentialsException {

        // DEBUG PURPOSES ONLY
    	// The registration handler send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.registrationHandler.login_request passing a USER_OBJECT (str at the moment)...
        log.debug("1. The registration handler send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.registrationHandler.login_request passing a USER_OBJECT  ");
        
        ObjectMapper mapper = new ObjectMapper();
        try {
	        rabbitTemplate.convertAndSend(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE, mapper.writeValueAsString(user));
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }
    
    public void testLoginMonitoring(LoginRequest user) throws MissingArgumentsException,WrongCredentialsException {

        // DEBUG PURPOSES ONLY
    	// The registration handler send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.registrationHandler.login_request passing a USER_OBJECT (str at the moment)...
        log.debug("1. The monitoring send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.monitoring.login_request passing a USER_OBJECT  ");
        
        ObjectMapper mapper = new ObjectMapper();
        try {
	        rabbitTemplate.convertAndSend(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE, mapper.writeValueAsString(user));
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }
    
    public void testCTR(RequestToken token) throws MissingArgumentsException,WrongCredentialsException {

        // DEBUG PURPOSES ONLY
    	// The registration handler send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.registrationHandler.login_request passing a USER_OBJECT (str at the moment)...
        log.debug("1. The platform RAP oring send a message to the symbIoTe.platformAAM exchange with a routing key symbIoTe.platformAAM.platformRAP.check_token_revocation_request passing a TOKEN_OBJECT  ");
        
        ObjectMapper mapper = new ObjectMapper();
        try {
	        rabbitTemplate.convertAndSend(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE, mapper.writeValueAsString(token));
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }
}
