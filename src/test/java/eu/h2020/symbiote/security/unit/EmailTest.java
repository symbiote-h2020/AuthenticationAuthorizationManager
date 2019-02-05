package eu.h2020.symbiote.security.unit;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetupTest;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.mail.Message;
import javax.mail.MessagingException;

import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = AuthenticationAuthorizationManager.class)
@TestPropertySource("/core.properties")
public class EmailTest {

    @Autowired
    public JavaMailSenderImpl mailSender;

    private GreenMail testSmtp;

    @Before
    public void testSmtpInit() {
        testSmtp = new GreenMail(ServerSetupTest.SMTP);
        testSmtp.start();
    }

    @Test
    public void testEmail() throws MessagingException {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("test@sender");
        message.setTo("test@receiver");
        message.setSubject("test subject");
        message.setText("test message");
        mailSender.send(message);

        Message[] messages = testSmtp.getReceivedMessages();
        assertEquals(1, messages.length);
        assertEquals("test subject", messages[0].getSubject());
        String body = GreenMailUtil.getBody(messages[0]).replaceAll("=\r?\n", "");
        assertEquals("test message", body);
    }

    @After
    public void cleanup() {
        testSmtp.stop();
    }
}