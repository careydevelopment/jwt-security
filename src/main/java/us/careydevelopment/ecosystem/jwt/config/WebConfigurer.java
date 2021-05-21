package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * This class gets extended in the Spring Boot application
 * The interceptor defined here is used to ensure requests come from a trusted source
 */
public abstract class WebConfigurer implements WebMvcConfigurer {

    protected String[] ipWhitelist;
    protected String privateIp;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new IpCheckerInterceptor(ipWhitelist, privateIp))
            .addPathPatterns("/**");
    }
}
