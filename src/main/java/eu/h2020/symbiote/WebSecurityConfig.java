package eu.h2020.symbiote;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${platformowner.username}")
    private String platformOwnerUsername;
    @Value("${platformowner.password}")
    private String platformOwnerPassword;

     @Override
     public void configure(WebSecurity web) throws Exception {
        web.ignoring()
            // Spring Security should completely ignore URLs starting with:
            .antMatchers("/login",
                    "/request_foreign_token",
                    "/check_home_token_revocation",
                    "/register",
                    "/unregister");
          	}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(
                        HttpMethod.GET,
                         "/static/**")
                .permitAll()
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/platform_owner_login")
                .permitAll()
                .and()
                .logout()
                .permitAll();

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser( platformOwnerUsername)
                .password( platformOwnerPassword)
                .roles("ADMIN");
    }
}