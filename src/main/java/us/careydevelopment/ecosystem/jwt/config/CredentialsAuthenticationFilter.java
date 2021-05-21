package us.careydevelopment.ecosystem.jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import us.careydevelopment.ecosystem.jwt.exception.UserServiceAuthenticationException;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;
import us.careydevelopment.ecosystem.jwt.model.JwtRequest;
import us.careydevelopment.ecosystem.jwt.model.JwtResponse;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;

/**
 * Users asking for access with a name and password get here
 *
 */
public class CredentialsAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
    private static final Logger LOG = LoggerFactory.getLogger(CredentialsAuthenticationFilter.class);

    protected AuthenticationManager authenticationManager;    
    protected JwtTokenUtil jwtUtil;
    
    /**
     * Instantiated from the Spring Boot application
     * 
     * @param man - standard Java class
     * @param jwtUtil - Spring-managed component
     */
    public CredentialsAuthenticationFilter(AuthenticationManager man, JwtTokenUtil jwtUtil) {
        this.authenticationManager = man;
        this.jwtUtil = jwtUtil;        
        this.setFilterProcessesUrl("/authenticate");
    }
    
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        Authentication auth = null;
        
        try {
            //translate the input to a request for a JWT
            JwtRequest jwtRequest = new ObjectMapper().readValue(req.getInputStream(), JwtRequest.class);
            LOG.debug("The JWT request is " + jwtRequest);
            
            //use authentication manager to validate credentials
            auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    jwtRequest.getUsername(), jwtRequest.getPassword()));
        } catch (Exception e) {
            LOG.error("Problem logging in user with credentials!", e);
            throw new UserServiceAuthenticationException(e.getMessage());
        }
        
        return auth;
    }
    
    
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, 
            FilterChain chain, Authentication auth) throws IOException {
        
        final BaseUser user = (BaseUser)auth.getPrincipal();
        final String token = jwtUtil.generateToken(user);
        Long expirationDate = jwtUtil.getExpirationDateFromToken(token).getTime();

        JwtResponse jwtResponse = new JwtResponse(token, user, expirationDate);
        
        String body = new ObjectMapper().writeValueAsString(jwtResponse);
        LOG.debug("Body response is " + body);
        
        res.getWriter().write(body);
        res.getWriter().flush();
    }
}
