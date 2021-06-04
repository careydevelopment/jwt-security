package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

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
