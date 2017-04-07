package eu.h2020.symbiote.commons.enums;

import com.fasterxml.jackson.annotation.JsonFormat;
import eu.h2020.symbiote.commons.json.RequestToken;

/**
 * Enumeration used as outcome in Cloud AAM 'Check Home Token Revocation' procedure.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.TokenManager#checkHomeTokenRevocation(RequestToken)
 */
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum Status{

    /**
     * Outcome associated to a token that is still valid after 'Check Home Token Revocation' procedure.
     */
    SUCCESS("success"),

    /**
     * Outcome associated to a token that is no longer valid after 'Check Home Token Revocation' procedure.
     */
    FAILURE("failure");

    private String status;

    private Status(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }


    public void setStatus(String status) {
        this.status = status;
    }
    
}
