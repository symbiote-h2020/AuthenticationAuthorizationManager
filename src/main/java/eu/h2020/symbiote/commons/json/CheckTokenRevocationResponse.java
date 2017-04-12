package eu.h2020.symbiote.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.commons.enums.Status;

/**
 * Class that defines the status of the checked token sent for revocation to
 * CloudAAM as part of a request.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CheckTokenRevocationResponse {

    private String status;

    public CheckTokenRevocationResponse() {
        this.status = null;
    }

    public CheckTokenRevocationResponse(Status token) {
        this.status = token.toString();
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status.toString();
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String toJson() {
        ObjectMapper om = new ObjectMapper();
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String toString() {
        return "CheckTokenRevocationResponse [status=" + status + "]";
    }

}
