package us.careydevelopment.ecosystem.jwt.exception;

import org.springframework.security.core.AuthenticationException;

public class TooManyFailedIpLoginsAuthenticationException extends AuthenticationException {
    
    private static final long serialVersionUID = -6313473860143052407L;

    public TooManyFailedIpLoginsAuthenticationException(String s) {
        super(s);
    }
}
