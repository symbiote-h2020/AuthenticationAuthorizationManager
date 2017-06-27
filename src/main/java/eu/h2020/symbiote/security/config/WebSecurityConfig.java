package eu.h2020.symbiote.security.config;

import eu.h2020.symbiote.security.constants.AAMConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                // Spring Security should completely ignore URLs starting with:
                .antMatchers("/webjars/**",
                        "/getCertificate",
                        "/register",
                        "/unregister",
                        "/test/**", // used for dirty federation tests
                        AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION,
                        AAMConstants.AAM_GET_AVAILABLE_AAMS,
                        AAMConstants.AAM_GET_CA_CERTIFICATE,
                        AAMConstants.AAM_LOGIN,
                        AAMConstants.AAM_REQUEST_FOREIGN_TOKEN
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/aam_owner_login")
                .permitAll()
                .and()
                .logout()
                .permitAll();

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(AAMOwnerUsername)
                .password(AAMOwnerPassword)
                .roles("ADMIN");
    }
}