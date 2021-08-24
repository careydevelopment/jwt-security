package us.careydevelopment.ecosystem.jwt.model;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;

public class JwtRequest {
	
    private String username;
    private String password;	
    private Boolean setCookie = false;
    
    @JsonProperty("g-recaptcha-response")
    private String recaptchaResponse;
	
    public JwtRequest() { }

    public JwtRequest(String username, String password) {
        this.setUsername(username);
        this.setPassword(password);
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public Boolean getSetCookie() {
        return setCookie;
    }

    public void setSetCookie(Boolean setCookie) {
        this.setCookie = setCookie;
    }
    
    public String getRecaptchaResponse() {
        return recaptchaResponse;
    }

    public void setRecaptchaResponse(String recaptchaResponse) {
        this.recaptchaResponse = recaptchaResponse;
    }

    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }
}
