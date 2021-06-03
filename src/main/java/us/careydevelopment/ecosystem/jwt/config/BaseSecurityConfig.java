package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import us.careydevelopment.ecosystem.jwt.constants.Authority;
import us.careydevelopment.ecosystem.jwt.exception.InvalidCredentialsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.exception.TooManyFailedIpLoginsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.exception.TooManyFailedLoginsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;
import us.careydevelopment.util.api.model.ResponseStatusCode;
import us.careydevelopment.util.api.response.ResponseUtil;
import us.careydevelopment.util.api.response.ResponseWriterUtil;

/**
 * Base class for security config
 * Assumes JWT-only authentication - override methods for credentials and JWT
 */
public abstract class BaseSecurityConfig extends WebSecurityConfigurerAdapter {

    //this can be overridden in the child class
    //TODO: probably use an ecosystem generic user rather than CRM-specific
    protected String[] allowedAuthorities = {Authority.CRM_USER};    

 
    protected AuthenticationProvider authenticationProvider;
    protected JwtTokenUtil jwtUtil;

    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }
        
    
    /**
     * Yep, we're using BearerTokenAuthenticationFilter even though it's designed for OAuth2.
     * That's because it's scalable - we'll probably go to OAuth2 one day.
     * Plus it works. So why complain?
     *
     * @return bearerTokenAuthenticationFilter
     * @throws Exception
     */
    protected BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter() throws Exception {
        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(authenticationManager());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
            
        return filter;
    }   
        
    
    /**
     * We get here if there's any kind of authentication failure.
     * 
     * The method examines the nature of the failure by looking at the 
     * exception. Then it returns the appropriate error response with
     * a message indicating what happened.
     */
    protected AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, ex) -> {
            if (ex instanceof InvalidCredentialsAuthenticationException) {
                ResponseUtil.invalidCredentials(response);
            } else if (ex instanceof TooManyFailedIpLoginsAuthenticationException) {
                ResponseUtil.tooManyFailedIpLogins(response);
            } else if (ex instanceof TooManyFailedLoginsAuthenticationException) {
                ResponseUtil.tooManyFailedLogins(response);
            } else {
                ResponseWriterUtil.writeResponse(response, ex.getMessage(), ResponseStatusCode.UNAUTHORIZED);                                  
            }
        };
    }
        
        
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {              
        httpSecurity
            .cors().and()
            .csrf().disable()
            .addFilter(bearerTokenAuthenticationFilter())
            .authorizeRequests()
            .anyRequest().hasAnyAuthority(allowedAuthorities).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }   
}
