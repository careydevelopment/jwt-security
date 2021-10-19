package us.careydevelopment.ecosystem.jwt.harness;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import us.careydevelopment.ecosystem.jwt.constants.Authority;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;

public class UserDetailsHarness {

    public static final String VALID_FIRST_NAME = "Manny";
    public static final String VALID_LAST_NAME = "Granados";
    public static final String VALID_USERNAME = "mgranados";
    public static final String VALID_ID = "444";
    public static final String VALID_EMAIL_ADDRESS = "you@toohottohandle.com";
    public static final String VALID_PASSWORD = "password";
    public static final String VALID_PHONE = "919-555-1212";

    public static final UserDetails getValidUserDetails() {
        UserDetails userDetails = new User(VALID_USERNAME, VALID_PASSWORD, List.of());
        return userDetails;
    }
    
    public static final BaseUser getValidBaseUser() {
        BaseUserImpl user = new BaseUserImpl(getValidUserDetails());
        user.setAuthorityNames(List.of(Authority.BASIC_ECOSYSTEM_USER));
        user.setId(VALID_ID);
        
        return user;
    }
    
    private static class BaseUserImpl extends BaseUser {

        private static final long serialVersionUID = -5365431484598356885L;
        
        BaseUserImpl(UserDetails userDetails) {
            setUsername(userDetails.getUsername());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public String getPassword() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean isAccountNonExpired() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public boolean isAccountNonLocked() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            // TODO Auto-generated method stub
            return false;
        }

        @Override
        public boolean isEnabled() {
            // TODO Auto-generated method stub
            return false;
        }
        
    }
}
