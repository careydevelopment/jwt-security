package us.careydevelopment.ecosystem.jwt.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import us.careydevelopment.ecosystem.jwt.exception.UserServiceAuthenticationException;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;

/**
 * Handles authentication with a JWT or name/password
 */
public abstract class CredentialsAndJwtAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialsAndJwtAuthenticationProvider.class);

    protected JwtUserDetailsService jwtUserDetailsService;
    
    protected JwtTokenUtil jwtUtil;

    
    @Override
    public boolean supports(Class<?> authentication) {
        LOG.debug("In supports");
        boolean b = authentication.equals(BearerTokenAuthenticationToken.class);
        
        return b;
    }
    
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.debug("In authenticate");
        BearerTokenAuthenticationToken bearerToken = (BearerTokenAuthenticationToken) authentication;
        Authentication auth = null;
        
        try {
            String token = bearerToken.getToken();
            
            //validate the token
            jwtUtil.validateTokenWithSignature(token);
            
            String username = jwtUtil.getUsernameFromToken(token);
            
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

            auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());            
            LOG.debug("Authentication token: " + auth);            
        } catch (IllegalArgumentException e) {
            LOG.debug("IllegalArgumentException", e);
            throw new UserServiceAuthenticationException("Invalid token");
        } catch (ExpiredJwtException e) {
            LOG.debug("ExpiredJtw", e);
            throw new UserServiceAuthenticationException("Token expired");
        } catch (SignatureException e) {
            LOG.debug("SignatureException", e);
            throw new UserServiceAuthenticationException("Invalid signature");
        }
        
        return auth;
    }
}
