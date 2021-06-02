package us.careydevelopment.ecosystem.jwt.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import us.careydevelopment.ecosystem.jwt.model.BaseUser;
import us.careydevelopment.ecosystem.jwt.model.JwtRequest;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.ecosystem.jwt.util.MultiReadHttpServletRequest;
import us.careydevelopment.ecosystem.jwt.util.ResponseWriterUtil;
import us.careydevelopment.util.date.DateConversionUtil;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class TooManyFailedRequestsFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(TooManyFailedRequestsFilter.class);

    private static final int MAX_LOGIN_ATTEMPTS = 4;
    private static final long FAILED_LOGIN_TIMEOUT_PERIOD = DateConversionUtil.NUMBER_OF_MILLISECONDS_IN_DAY;

    
    @Autowired
    private JwtUserDetailsService userService;

    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {

        boolean allowedIn = true;
    
        System.err.println("Checking for too many requests");
        
        if (HttpMethod.POST.name().equals(request.getMethod())) {
            try {
                //gotta get the contents in a roundabout way so we don't burn out the input stream
                //before actual login
                MultiReadHttpServletRequest wrappedRequest = new MultiReadHttpServletRequest(request);
                request = wrappedRequest;
                String json = request.getReader().lines().collect(Collectors.joining());
                
                JwtRequest jwtRequest = new ObjectMapper().readValue(json, JwtRequest.class);
                LOG.debug("The JWT request in interceptor is " + jwtRequest);
        
                if (jwtRequest != null && jwtRequest.getUsername() != null) {
                    BaseUser user = (BaseUser)userService.loadUserByUsername(jwtRequest.getUsername());        
                    allowedIn = checkForFailedLogins(user);
                } else {
                    LOG.error("Can't parse login request!");
                    allowedIn = false;
                }
            } catch (Exception e) {
                LOG.error("Problem logging in!", e);
                allowedIn = false;
            }
        }
        
        System.err.println("allowedin is " + allowedIn);
        
        if (!allowedIn) {
            System.err.println("Going here");
            //response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Too many failed login attempts. Please try again tomorrow.");
            
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());                
            ResponseWriterUtil.writeErrorResponse(response, "Too many failed login attempts. Please try again tomorrow");
        } else {
            filterChain.doFilter(request, response);            
        }
    }
    
    
    private boolean checkForFailedLogins(BaseUser user) throws IOException {
        boolean allowedIn = true;
        
        if (user.getFailedLoginAttempts() != null) {
            if (user.getFailedLoginAttempts() > MAX_LOGIN_ATTEMPTS) {
                allowedIn = checkDateThreshold(user);
            }
        }

        return allowedIn;
    }
    
    
    private boolean checkDateThreshold(BaseUser user) throws IOException {
        boolean allowedIn = true;
        
        if (user.getLastFailedLoginTime() != null) {
            Long now = System.currentTimeMillis();
            Long difference = now - user.getLastFailedLoginTime();
            
            if (difference < FAILED_LOGIN_TIMEOUT_PERIOD) {
                allowedIn = false;
            }
        }
        
        return allowedIn;
    }
}
