package eu.h2020.symbiote.security.swagger;


import com.google.common.base.Predicates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import springfox.bean.validators.configuration.BeanValidatorPluginsConfiguration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.HashSet;
import java.util.Set;

import static springfox.documentation.builders.PathSelectors.ant;

@EnableSwagger2
@Configuration
@Import(BeanValidatorPluginsConfiguration.class)
public class SwaggerConfig {
    private static final Logger LOG = LoggerFactory.getLogger(SwaggerConfig.class);

    @Bean
    public Docket restApi() {
        LOG.info("restApi()");
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .useDefaultResponseMessages(false)
                .produces(producesSet())
                .select()
                .paths(Predicates.and(ant("/**"), Predicates.not(ant("/error")), Predicates.not(ant("/test/**"))))
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Authentication and Authorization Manager")
                .description("Authentication and Authorization Manager API Description")
                .contact(new Contact("Mikołaj Dobski", "https://www.symbiote-h2020.eu/", "mikolaj.dobski@man.poznan.pl"))
                .license("GNU Lesser General Public License v3.0")
                .licenseUrl("https://github.com/symbiote-h2020/AuthenticationAuthorizationManager/blob/master/LICENSE.txt")
                .version("3.0")
                .build();
    }

    private Set<String> producesSet() {
        Set<String> set = new HashSet<String>();
        set.add("application/json");

        return set;
    }
}
