package us.careydevelopment.ecosystem.jwt.config;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import us.careydevelopment.ecosystem.jwt.constants.Authority;
import us.careydevelopment.ecosystem.jwt.util.JwtTokenUtil;
import us.careydevelopment.ecosystem.jwt.util.ResponseWriterUtil;

/**
 * This class gets extended in the Spring Boot application
 */
public abstract class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //this can be overridden in the child class
    //TODO: probably use an ecosystem generic user rather than CRM-specific
    protected String[] allowedAuthorities = {Authority.CRM_USER};    
    
    protected UserDetailsService jwtUserDetailsService;
    protected JwtAuthenticationProvider jwtAuthenticationProvider;
    protected JwtTokenUtil jwtUtil;
    
	
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthenticationProvider);
	auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
    }

	
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * For now, we're relying on IpCheckerInterceptor rather than CORS.
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
        CredentialsAuthenticationFilter filter = new CredentialsAuthenticationFilter(authenticationManager(), jwtUtil);
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());

        return filter;
    }
	
	
    private AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, ex) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
	    response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
	        
	    ResponseWriterUtil.writeErrorResponse(response, ex.getMessage());			
	};
    }
	
	
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {		
        httpSecurity
            .cors().and()
            .csrf().disable()
            .addFilter(bearerTokenAuthenticationFilter())
            .addFilter(credentialsAuthenticationFilter())       
            .authorizeRequests()
            .anyRequest().hasAnyAuthority(allowedAuthorities).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }	
}