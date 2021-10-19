package us.careydevelopment.ecosystem.jwt.util;

import java.util.Collection;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import us.careydevelopment.ecosystem.jwt.constants.Authority;
import us.careydevelopment.ecosystem.jwt.harness.UserDetailsHarness;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;

public class JwtTokenUtilTest {

    private static final String SECRET = "secret";
    
    private JwtTokenUtilImpl util = new JwtTokenUtilImpl();
    
    private final BaseUser user = UserDetailsHarness.getValidBaseUser();
    private final String token = util.generateToken(user);
    
    @Test
    public void testGetAuthorities() {
        Collection<? extends GrantedAuthority> authorities = util.getAuthorities(token);

        Assertions.assertEquals(1, authorities.size());
        authorities.forEach(authority -> {
            Assertions.assertEquals(Authority.BASIC_ECOSYSTEM_USER.toString(), authority.getAuthority());
        });
    }
    
    @Test
    public void testValidateGetTokenWithSignature() {
        util.validateTokenWithSignature(token);
        //should not throw an exception
    }
    
    @Test
    public void testValidateToken() {
        Boolean validated = util.validateToken(token);
        Assertions.assertTrue(validated);
    }
    
    @Test
    public void testGetClaimsFromToken() {
        String id = util.getClaimFromTokenByName("id", token);
        Assertions.assertEquals(UserDetailsHarness.VALID_ID, id);
    }
    
    @Test
    public void testGetUsernameFromToken() {
        String username = util.getUsernameFromToken(token);
        Assertions.assertEquals(UserDetailsHarness.VALID_USERNAME, username);
    }
    
    @Test
    public void testValidateTokenWithUser() {
        Boolean validated = util.validateToken(user, token);
        Assertions.assertTrue(validated);
    }
    
    private static class JwtTokenUtilImpl extends JwtTokenUtil {
        public JwtTokenUtilImpl() {
            this.jwtSecret = SECRET;
        }
    }
}
