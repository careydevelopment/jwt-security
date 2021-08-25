package us.careydevelopment.ecosystem.jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import us.careydevelopment.ecosystem.jwt.constants.CookieConstants;
import us.careydevelopment.ecosystem.jwt.exception.InvalidCredentialsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.exception.UserServiceAuthenticationException;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;
import us.careydevelopment.ecosystem.jwt.model.IpTracker;
import us.careydevelopment.ecosystem.jwt.model.JwtRequest;
import us.careydevelopment.ecosystem.jwt.model.JwtResponse;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;
import us.careydevelopment.ecosystem.jwt.util.LoginAttemptsUtil;
import us.careydevelopment.ecosystem.jwt.util.RecaptchaUtil;

/**
 * Users asking for access with a name and password get here
 */
public class CredentialsAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
    private static final Logger LOG = LoggerFactory.getLogger(CredentialsAuthenticationFilter.class);
    
    protected AuthenticationManager authenticationManager;    
    protected JwtTokenUtil jwtUtil;
    protected JwtUserDetailsService jwtUserDetailsService;
    protected IpTracker ipTracker;
    protected RecaptchaUtil recaptchaUtil;
    
    private Boolean createCookie = false;
    
    
    /**
     * Instantiated from the Spring Boot application
     * 
     * @param man - standard Java class
     * @param jwtUtil - Spring-managed component
     */
    public CredentialsAuthenticationFilter(AuthenticationManager man) {
        this.authenticationManager = man;        
        this.setFilterProcessesUrl("/authenticate");
    }

    
    public void setJwtTokenUtil(JwtTokenUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    
    
    public void setIpTracker(IpTracker ipTracker) {
        this.ipTracker = ipTracker;
    }
    
    
    public void setUserDetailsService(JwtUserDetailsService jwtUserDetailsService) {
        this.jwtUserDetailsService = jwtUserDetailsService;
    }
    
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        JwtRequest jwtRequest = null;
        ObjectMapper mapper = new ObjectMapper();
        LoginAttemptsUtil loginAttemptsUtil = new LoginAttemptsUtil(jwtUserDetailsService, ipTracker);
        
        try {
            //make sure the user hasn't failed login too many times from this IP address
            loginAttemptsUtil.checkIpValidity(req);            

            //construct the JwtRequest object from the input stream
            jwtRequest = mapper.readValue(req.getInputStream(), JwtRequest.class);

            if (recaptchaCheck(jwtRequest)) {
                //now check to make sure this user hasn't had too many failed login attempts
                loginAttemptsUtil.checkMaxLoginAttempts(jwtRequest);
                
                //handle login
                return handleLogin(jwtRequest);                    
            } else {
                throw new UserServiceAuthenticationException("Google thinks you're a bot");
            }
        } catch (BadCredentialsException e) {
            LOG.error("Bad credentials!", e);
            
            //gotta log to both the user service and ip tracker
            //because the user service tracks failed login attempts per user
            //while the ip tracker tracks failed login attempts per ip
            jwtUserDetailsService.updateFailedLoginAttempts(jwtRequest.getUsername());
            ipTracker.unsuccessfulLogin(jwtRequest.getUsername(), req.getRemoteAddr());
            
            throw new InvalidCredentialsAuthenticationException(e.getMessage());
        } catch (JsonMappingException e) {
            LOG.error("Problem logging in user with credentials!", e);
            throw new UserServiceAuthenticationException(e.getMessage());
        } catch (IOException e) {
            LOG.error("Problem logging in user with credentials!", e);
            throw new UserServiceAuthenticationException(e.getMessage());
        }
    }

    
    private boolean recaptchaCheck(JwtRequest jwtRequest) throws IOException {
        boolean pass = true;
        
        if (recaptchaUtil != null) {
            float score = recaptchaUtil.createAssessment(jwtRequest.getRecaptchaResponse());
            pass = (score >= RecaptchaUtil.RECAPTCHA_MIN_SCORE);
        }

        return pass;
    }
    
    
    
    /**
     * Uses the authentication manager to complete the login process
     * Will throw an exception if the credentials aren't valid.
     */
    private Authentication handleLogin(JwtRequest jwtRequest) {
        Authentication auth = null;
        
        if (jwtRequest != null) {
            this.createCookie = jwtRequest.getSetCookie();
            
            //use authentication manager to validate credentials
            auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    jwtRequest.getUsername(), jwtRequest.getPassword()));
        } else {
            throw new UserServiceAuthenticationException("Problem getting login credentials!");
        }
        
        return auth;
    }
        
    
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, 
            FilterChain chain, Authentication auth) throws IOException {

        final BaseUser user = (BaseUser)auth.getPrincipal();
        final String token = jwtUtil.generateToken(user);
        final Long expirationDate = jwtUtil.getExpirationDateFromToken(token).getTime();

        if (createCookie) {
            Cookie cookie = createCookie(token);
            res.addCookie(cookie);            
        }
        
        //log a successful authentication to iplog collection
        ipTracker.successfulLogin(user.getUsername(), req.getRemoteAddr());
        
        //log a successful authentication to user collection
        jwtUserDetailsService.successfulLogin(user.getUsername());
        
        JwtResponse jwtResponse = new JwtResponse(token, user, expirationDate);
        
        String body = new ObjectMapper().writeValueAsString(jwtResponse);
        LOG.debug("Body response is " + body);
        
        res.getWriter().write(body);
        res.getWriter().flush();
    }
    
    
    private Cookie createCookie(final String content) {
        final Cookie cookie = new Cookie(CookieConstants.ACCESS_TOKEN_COOKIE_NAME, content);
        
        cookie.setMaxAge(JwtTokenUtil.JWT_TOKEN_VALIDITY) ;
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(true);
                
        return cookie;
    }
}