package us.careydevelopment.ecosystem.jwt.repository;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserDetailsRepository {

    public UserDetails findByUsername(String username);
    
    public UserDetails findByEmail(String emailAddress);
}
