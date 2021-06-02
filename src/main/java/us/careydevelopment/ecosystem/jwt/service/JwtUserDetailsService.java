package us.careydevelopment.ecosystem.jwt.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import us.careydevelopment.ecosystem.jwt.repository.UserDetailsRepository;

/**
 * This is how we get user info from the database.
 * It's designed to be abstract - child class can implement a repo that uses MongoDB or MySQL
 * 
 * The Spring Boot application will extend this class and set a concrete implementation of UserDetailsRepository
 */
public abstract class JwtUserDetailsService implements UserDetailsService {

    protected UserDetailsRepository userDetailsRepository;

    
    /**
     * Because we aim to please, this method checks to see if the user logged in with an email address
     * or a user name
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = userDetailsRepository.findByUsername(username);

        if (user != null) {         
            return user;
        } else {
            user = userDetailsRepository.findByEmail(username);
            
            if (user != null) {
                return user;
            } else {
                throw new UsernameNotFoundException("User not found with username: " + username);               
            }
        }
    }    
}