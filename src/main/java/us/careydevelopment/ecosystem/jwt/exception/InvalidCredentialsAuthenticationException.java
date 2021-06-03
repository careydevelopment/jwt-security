package us.careydevelopment.ecosystem.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidCredentialsAuthenticationException extends AuthenticationException {
    
    private static final long serialVersionUID = 7799512893588563557L;

    public InvalidCredentialsAuthenticationException(String s) {
        super(s);
    }
}
