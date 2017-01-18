package eu.h2020.symbiote.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by Nemanja on 14.12.2016.
 */
public class RequestToken {

    private String token;

    public RequestToken() {
        this.token = null;
    }

    public RequestToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
    
    public String toJson(){
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
		return "RequestToken [token=" + token + "]";
	}
    
    
}
