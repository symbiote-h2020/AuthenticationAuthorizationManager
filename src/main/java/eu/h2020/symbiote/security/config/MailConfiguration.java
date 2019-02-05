package eu.h2020.symbiote.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
@PropertySource("classpath:mail.properties")
public class MailConfiguration {

    private final String protocol;
    private final String host;
    private final int port;
    private final String auth;
    private final String starttls;
    private final String username;
    private final String password;

    public MailConfiguration(@Value("${mail.protocol}") String protocol,
                             @Value("${mail.host}") String host,
                             @Value("${mail.port}") int port,
                             @Value("${mail.smtp.auth}") String auth,
                             @Value("${mail.smtp.starttls.enable}") String starttls,
                             @Value("${mail.username}") String username,
                             @Value("${mail.password}") String password) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.auth = auth;
        this.starttls = starttls;
        this.username = username;
        this.password = password;
    }

    @Bean
    public JavaMailSenderImpl getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        Properties mailProperties = new Properties();
        mailProperties.put("mail.smtp.auth", auth);
        mailProperties.put("mail.smtp.starttls.enable", starttls);

        mailSender.setJavaMailProperties(mailProperties);
        mailSender.setProtocol(protocol);
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        return mailSender;
    }
}