package eu.h2020.symbiote.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ErrorResponseContainer {

	private String errorMessage;
	private int errorCode;

	public ErrorResponseContainer() {
		// TODO Auto-generated constructor stub
	}

	public ErrorResponseContainer(String errorMessage, int errorCode) {
		super();
		this.errorMessage = errorMessage;
		this.errorCode = errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public int getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(int errorCode) {
		this.errorCode = errorCode;
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
}