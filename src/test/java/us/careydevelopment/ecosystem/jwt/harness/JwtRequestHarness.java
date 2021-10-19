package us.careydevelopment.ecosystem.jwt.harness;

import us.careydevelopment.ecosystem.jwt.model.JwtRequest;

public class JwtRequestHarness {

    public static JwtRequest getValidJwtRequest() {
        JwtRequest request = new JwtRequest();
        
        request.setPassword(UserDetailsHarness.VALID_PASSWORD);
        request.setUsername(UserDetailsHarness.VALID_USERNAME);
        
        return request;
    }
}
