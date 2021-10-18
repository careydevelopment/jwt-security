package us.careydevelopment.ecosystem.jwt.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import us.careydevelopment.ecosystem.jwt.harness.UserDetailsHarness;
import us.careydevelopment.ecosystem.jwt.repository.UserDetailsRepository;


@ExtendWith(MockitoExtension.class)
public class JwtUserDetailsServiceTest {

    @Mock
    private UserDetailsRepository repo;
    
    @InjectMocks
    private UserDetailsService service = new UserDetailsServiceImpl();
    
    @Test
    public void testLoadUserByUsernameWithValidUsername() {
       final String username = UserDetailsHarness.VALID_USERNAME;
       final UserDetails userDetails = UserDetailsHarness.getValidUserDetails();
       
       Mockito.when(repo.findByUsername(username)).thenReturn(userDetails);
       
       UserDetails returnedUser = service.loadUserByUsername(username);
       
       Assertions.assertEquals(UserDetailsHarness.VALID_USERNAME, returnedUser.getUsername());
       Assertions.assertEquals(UserDetailsHarness.VALID_PASSWORD, returnedUser.getPassword());
    }
    
    @Test
    public void testLoadUserByUsernameWithValidEmailAddress() {
       final String username = UserDetailsHarness.VALID_EMAIL_ADDRESS;
       
       final UserDetails userDetails = UserDetailsHarness.getValidUserDetails();
       
       Mockito.when(repo.findByUsername(username)).thenReturn(null);
       Mockito.when(repo.findByEmail(username)).thenReturn(userDetails);
       
       UserDetails returnedUser = service.loadUserByUsername(username);
       
       Assertions.assertEquals(UserDetailsHarness.VALID_USERNAME, returnedUser.getUsername());
       Assertions.assertEquals(UserDetailsHarness.VALID_PASSWORD, returnedUser.getPassword());
    }
    
    private static class UserDetailsServiceImpl extends JwtUserDetailsService {

        @Override
        public void updateFailedLoginAttempts(String username) {
            // TODO Auto-generated method stub
            
        }

        @Override
        public void successfulLogin(String username) {
            // TODO Auto-generated method stub
            
        }
        
    }
}
