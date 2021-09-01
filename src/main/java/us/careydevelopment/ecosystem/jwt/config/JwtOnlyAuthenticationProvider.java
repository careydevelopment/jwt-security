package us.careydevelopment.ecosystem.jwt.config;

import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import us.careydevelopment.ecosystem.jwt.exception.UserServiceAuthenticationException;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;

/**
 * Handles authentication with a JWT instead of name/password
 */
public abstract class JwtOnlyAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(JwtOnlyAuthenticationProvider.class);

    protected JwtUserDetailsService jwtUserDetailsService;
    
    protected JwtTokenUtil jwtUtil;

    
    @Override
    public boolean supports(Class<?> authentication) {
        LOG.debug("In supports jwt only");
        return authentication.equals(BearerTokenAuthenticationToken.class);
    }
    
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.debug("Attempting authentication jwt only");
        BearerTokenAuthenticationToken bearerToken = (BearerTokenAuthenticationToken) authentication;
        Authentication auth = null;
        
        try {          
            String token = bearerToken.getToken();
            
            //validate the token
            jwtUtil.validateTokenWithSignature(token);
            
            Collection<? extends GrantedAuthority> authorities = jwtUtil.getAuthorities(token);
            String username = jwtUtil.getUsernameFromToken(token);

            auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
            LOG.debug("Authentication token: " + auth);            
        } catch (IllegalArgumentException e) {
            LOG.debug("Problem authentication", e);
            throw new UserServiceAuthenticationException("Invalid token");
        } catch (ExpiredJwtException e) {
            LOG.debug("Expired token", e);
            throw new UserServiceAuthenticationException("Token expired");
        } catch (SignatureException e) {
            LOG.debug("Signature issue", e);
            throw new UserServiceAuthenticationException("Invalid signature");
        }
        
        return auth;
    }
}
