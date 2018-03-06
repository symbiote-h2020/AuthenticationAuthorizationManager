package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertEquals;

@TestPropertySource("/smart_space.properties")
public class SmartSpaceUnitTests extends AbstractAAMTestSuite {

    @Autowired
    CertificationAuthorityHelper certificationAuthorityHelper;

    @Test
    public void smartSpaceAAMDeploymentTypeSuccess() {
        assertEquals(IssuingAuthorityType.SMART_SPACE, certificationAuthorityHelper.getDeploymentType());
    }


}
