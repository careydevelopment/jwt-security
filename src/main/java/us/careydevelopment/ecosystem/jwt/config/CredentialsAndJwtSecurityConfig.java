package us.careydevelopment.ecosystem.jwt.config;

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

/**
 * This class gets extended in the Spring Boot application
 * Handles security config for applications that support user login and JWT 
 */
public abstract class CredentialsAndJwtSecurityConfig extends BaseSecurityConfig  {

    protected JwtUserDetailsService jwtUserDetailsService;
    protected IpTracker ipTracker;
    
        
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
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
        CredentialsAuthenticationFilter filter = new CredentialsAuthenticationFilter(authenticationManager());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setJwtTokenUtil(jwtUtil);
        filter.setUserDetailsService(jwtUserDetailsService);
        filter.setIpTracker(ipTracker);
        
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
            .antMatchers("/check/**").permitAll()
            .antMatchers("/user/simpleSearch").permitAll()
            .anyRequest().hasAnyAuthority(getAllowedAuthorities()).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }   
}
