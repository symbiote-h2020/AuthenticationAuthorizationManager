package eu.h2020.symbiote.security.commons.jwt;

import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests checking if
 * Created by Mikołaj on 02.05.2017.
 */
@Ignore("Please implement!!!")
public class JWTClaimsTest extends AuthenticationAuthorizationManagerTests {
    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void getJti() throws Exception {
        // check if two tokens get different Id
    }

    @Test
    public void getAlg() throws Exception {
        // check if configured algo is here
    }

    @Test
    public void getIss() throws Exception {
        // check if deployment id is here
    }

    @Test
    public void getSub() throws Exception {
        // check if registered username is here
    }

    @Test
    public void getIat() throws Exception {
        // check if issue date is reasonable
    }

    @Test
    public void getExp() throws Exception {
        // covered somewhere in revocation
    }

    @Test
    public void getIpk() throws Exception {
        // check if AAM public key is here
    }

    @Test
    public void getSpk() throws Exception {
        // this one is broken
    }

    @Test
    public void getAtt() throws Exception {
        // this is covered round the other test
    }

    @Test
    public void getTtyp() throws Exception {
        // this is covered round the other test
    }

}