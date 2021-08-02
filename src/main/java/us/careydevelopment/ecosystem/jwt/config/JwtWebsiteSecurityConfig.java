package us.careydevelopment.ecosystem.jwt.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

public abstract class JwtWebsiteSecurityConfig extends JwtOnlySecurityConfig {

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {              
        httpSecurity
            .cors().and()
            .csrf().disable()
            .addFilter(bearerTokenAuthenticationFilter())
            .authorizeRequests()
            .antMatchers("/").permitAll()
            .antMatchers("/error/**").permitAll()
            .antMatchers("/blog/**").permitAll()
            .antMatchers("/about/**").permitAll()
            .antMatchers("/images/**").permitAll()
            .antMatchers("/video/**").permitAll()
            .antMatchers("/posts/**").permitAll()
            .antMatchers("/search/**").permitAll()
            .antMatchers("/img/**").permitAll()
            .antMatchers("/css/**").permitAll()
            .antMatchers("/js/**").permitAll()
            .antMatchers("/sitemap_index.xml").permitAll()
            .antMatchers("/feed").permitAll()
            .antMatchers("/contact").permitAll()
            .antMatchers("/tag/**").permitAll()
            .antMatchers("/category/**").permitAll()
            .antMatchers("/ads.txt").permitAll()
            .anyRequest().hasAnyAuthority(getAllowedAuthorities()).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
