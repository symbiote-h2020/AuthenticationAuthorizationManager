package eu.h2020.symbiote.rabbitmq.consumers;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.services.LoginService;

@Service
public class LoginConsumerService {

	@Autowired
	private LoginService loginService;
	@Autowired
	private RabbitTemplate rabbitTemplate;

	public LoginConsumerService() {
		
	}

	public void receiveMessage(LoginRequest receivedReq) {
		try {
			LoginRequest user = new LoginRequest(receivedReq.getUsername(),receivedReq.getPassword());
			RequestToken token = loginService.login(user);
			//Platform AAM sends the login response back toRegistration Handler
			rabbitTemplate.convertAndSend(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE,
					token.toJson());
		} catch (MissingArgumentsException | WrongCredentialsException e) {
			//Platform AAM sends the error response back toRegistration Handler

			rabbitTemplate.convertAndSend(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE,
					(new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson());
		}
	}

}
