package us.careydevelopment.ecosystem.jwt.harness;

import java.util.List;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

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
}
