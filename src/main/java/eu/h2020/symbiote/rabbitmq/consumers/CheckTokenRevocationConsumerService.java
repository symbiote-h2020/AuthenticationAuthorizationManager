package eu.h2020.symbiote.rabbitmq.consumers;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.services.TokenService;

@Service
public class CheckTokenRevocationConsumerService {

	@Autowired
	private TokenService tokenService;
	@Autowired
	private RabbitTemplate rabbitTemplate;

	public CheckTokenRevocationConsumerService() {

	}

	public void receiveMessage(RequestToken receivedReq) {
		CheckTokenRevocationResponse status = tokenService.checkHomeTokenRevocation(receivedReq);
		// Platform AAM sends the login response back toRegistration Handler
		rabbitTemplate.convertAndSend(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE,
				status.toString());
	}

}
