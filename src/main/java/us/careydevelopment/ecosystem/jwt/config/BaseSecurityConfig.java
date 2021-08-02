package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

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
    private String[] allowedAuthorities = { Authority.CRM_USER };    
    
    protected AuthenticationProvider authenticationProvider;
    protected JwtTokenUtil jwtUtil;

    protected String[] getAllowedAuthorities() {
        return allowedAuthorities;
    }
    
    
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
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
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
            .antMatchers("/check/**").permitAll()
            .anyRequest().hasAnyAuthority(getAllowedAuthorities()).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
    
    
    /**
     * For now, we're relying on IpCheckerFilter rather than CORS.
     * That's because Kubernetes assigns new ports with each pod.
     * We just need to check the IP address whereas CORS looks at ports too.
     * 
     * @return corsFilter
     */
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        
        return new CorsFilter(source);
    }
}
 