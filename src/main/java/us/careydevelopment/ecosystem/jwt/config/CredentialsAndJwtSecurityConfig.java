package us.careydevelopment.ecosystem.jwt.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;

import us.careydevelopment.ecosystem.jwt.model.IpTracker;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.ecosystem.jwt.util.RecaptchaUtil;

/**
 * This class gets extended in the Spring Boot application
 * Handles security config for applications that support user login and JWT 
 */
public abstract class CredentialsAndJwtSecurityConfig extends BaseSecurityConfig  {
    
    private static final Logger LOG = LoggerFactory.getLogger(CredentialsAndJwtSecurityConfig.class);

    protected JwtUserDetailsService jwtUserDetailsService;
    protected IpTracker ipTracker;

    //template method pattern for this one
    //it's a Spring component that requires a constructor
    //and gets set with @Bean in the child class
    public abstract RecaptchaUtil recaptchaUtil();
    
    
    protected String[] permitAllUrls() {
        String[] permitAll = { "/" };
        return permitAll;
    }
    
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        LOG.debug("In configure global");
        auth.authenticationProvider(authenticationProvider);
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
    }

        
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
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
        LOG.debug("In bearerTokenAuthenticationFilter");
        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(authenticationManager());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
            
        return filter;
    }
    
    
    /**
    
     * This filter handles name/password authentication
     * 
     * @return credentialsAuthenticationFilter
     * @throws Exception
     */
    protected CredentialsAuthenticationFilter credentialsAuthenticationFilter() throws Exception {
        LOG.debug("In credentialsauthenticationfilter");
        CredentialsAuthenticationFilter filter = new CredentialsAuthenticationFilter(authenticationManager());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setJwtTokenUtil(jwtUtil);
        filter.setUserDetailsService(jwtUserDetailsService);
        filter.setIpTracker(ipTracker);
        filter.recaptchaUtil = recaptchaUtil();
        
        return filter;
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {              
        httpSecurity
            .cors().and()
            .csrf().disable()
            .addFilter(bearerTokenAuthenticationFilter())
            .addFilter(credentialsAuthenticationFilter())
            .authorizeRequests()
            
            //used to check if the registering user is using a 
            //duplicate username or email address
            .antMatchers("/check/**").permitAll()
            
            .antMatchers(permitAllUrls()).permitAll()
            .anyRequest().hasAnyAuthority(getAllowedAuthorities()).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }   
}