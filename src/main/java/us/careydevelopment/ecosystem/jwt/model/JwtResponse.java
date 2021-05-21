package us.careydevelopment.ecosystem.jwt.model;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

public class JwtResponse {

    private final String token;
    private final BaseUser user;
    private final Long expirationDate;

    public JwtResponse(String token, BaseUser user, Long expirationDate) {
        this.token = token;
        this.user = user;
        this.expirationDate = expirationDate;
    }
	
    public Long getExpirationDate() {
        return expirationDate;
    }

    public String getToken() {
        return this.token;
    }

    public BaseUser getUser() {
        return user;
    }	

    public String toString() {
	return ReflectionToStringBuilder.toString(this);
    }
}
