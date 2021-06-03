package us.careydevelopment.ecosystem.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class TooManyFailedLoginsAuthenticationException extends AuthenticationException {
    
    private static final long serialVersionUID = 5368673516685167890L;

    public TooManyFailedLoginsAuthenticationException(String s) {
        super(s);
    }
}
