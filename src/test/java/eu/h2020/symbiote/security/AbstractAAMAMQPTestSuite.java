package eu.h2020.symbiote.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Import;

@Import({RabbitTestConfiguration.class})
public abstract class AbstractAAMAMQPTestSuite extends AbstractAAMTestSuite {
    @Value("${rabbit.queue.manage.user.request}")
    protected String userManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.user.request}")
    protected String userManagementRequestRoutingKey;

    @Value("${rabbit.queue.manage.platform.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String platformManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.platform.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String platformManagementRoutingKey;

    @Value("${rabbit.queue.manage.smartspace.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String smartSpaceManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.smartspace.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String smartSpaceManagementRoutingKey;

    @Value("${rabbit.queue.manage.revocation.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String revocationRequestQueue;
    @Value("${rabbit.queue.validate.request}")
    protected String validateRequestQueue;

    @Value("${rabbit.queue.get.user.details}")
    protected String getUserDetailsQueue;

    @Value("${rabbit.host}")
    private String rabbitHost;
    @Value("${rabbit.username}")
    private String rabbitUsername;
    @Value("${rabbit.password}")
    private String rabbitPassword;

}
