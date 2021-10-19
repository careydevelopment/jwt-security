package us.careydevelopment.ecosystem.jwt.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import us.careydevelopment.ecosystem.jwt.exception.TooManyFailedLoginsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.harness.JwtRequestHarness;
import us.careydevelopment.ecosystem.jwt.harness.UserDetailsHarness;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;
import us.careydevelopment.ecosystem.jwt.model.IpTracker;
import us.careydevelopment.ecosystem.jwt.model.JwtRequest;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;

@ExtendWith(MockitoExtension.class)
public class LoginAttemptsUtilTest {

    @Mock
    private JwtUserDetailsService jwtUserDetailsService;
    
    @Mock
    private IpTracker ipTracker;
    
    @InjectMocks
    private LoginAttemptsUtil util = new LoginAttemptsUtil(jwtUserDetailsService, ipTracker);
    
    @Test
    public void testCheckMaxLoginAttemptsExceeded() {
        JwtRequest request = JwtRequestHarness.getValidJwtRequest();
        BaseUser user = UserDetailsHarness.getValidBaseUser();
        user.setFailedLoginAttempts(5);
        user.setLastFailedLoginTime(System.currentTimeMillis() - 20000);
                
        Mockito.when(jwtUserDetailsService.loadUserByUsername(Mockito.anyString())).thenReturn(user);
        
        Assertions.assertThrows(TooManyFailedLoginsAuthenticationException.class, () -> util.checkMaxLoginAttempts(request));
    }
    
    @Test
    public void testCheckMaxLoginAttemptsOnlyOneFailed() {
        JwtRequest request = JwtRequestHarness.getValidJwtRequest();
        BaseUser user = UserDetailsHarness.getValidBaseUser();
        user.setFailedLoginAttempts(1);
        user.setLastFailedLoginTime(System.currentTimeMillis() - 20000);
                
        Mockito.when(jwtUserDetailsService.loadUserByUsername(Mockito.anyString())).thenReturn(user);
        util.checkMaxLoginAttempts(request);
        
        //no exception
    }
    
    @Test
    public void testCheckMaxLoginAttemptsOutsideOfDateThreshold() {
        JwtRequest request = JwtRequestHarness.getValidJwtRequest();
        BaseUser user = UserDetailsHarness.getValidBaseUser();
        user.setFailedLoginAttempts(1);
        user.setLastFailedLoginTime(System.currentTimeMillis() - 500000);
                
        Mockito.when(jwtUserDetailsService.loadUserByUsername(Mockito.anyString())).thenReturn(user);
        util.checkMaxLoginAttempts(request);
        
        //no exception
    }
    
    @Test
    public void testCheckIpValidityValid() {
        final String remoteAddr = "1.1.1.1";
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        
        Mockito.when(ipTracker.fetchIpFailureRecord(Mockito.anyString(), Mockito.anyLong())).thenReturn(null);
        
        util.checkIpValidity(request);
        
        //no exception
    }
}
