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
    
    
    /**
     * For now, we're relying on IpCheckerFilter rather than CORS.
     * That's because Kubernetes assigns new ports with each pod.
     * We just need to check the IP address whereas CORS looks at ports too.
     * 
     * Note: this filter is only used for JWT-only authentication APIs.
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
