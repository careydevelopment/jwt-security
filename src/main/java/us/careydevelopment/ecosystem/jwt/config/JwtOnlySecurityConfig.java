package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

/**
 * This class gets extended in the Spring Boot application
 * Handles authentication with just a JWT - no username/passwords allowed
 */
public abstract class JwtOnlySecurityConfig extends BaseSecurityConfig {
    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }
    
}
