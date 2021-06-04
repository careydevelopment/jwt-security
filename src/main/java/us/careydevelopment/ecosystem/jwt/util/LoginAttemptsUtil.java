package us.careydevelopment.ecosystem.jwt.util;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import us.careydevelopment.ecosystem.jwt.exception.TooManyFailedIpLoginsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.exception.TooManyFailedLoginsAuthenticationException;
import us.careydevelopment.ecosystem.jwt.exception.UserServiceAuthenticationException;
import us.careydevelopment.ecosystem.jwt.model.BaseIpLog;
import us.careydevelopment.ecosystem.jwt.model.BaseUser;
import us.careydevelopment.ecosystem.jwt.model.IpTracker;
import us.careydevelopment.ecosystem.jwt.model.JwtRequest;
import us.careydevelopment.ecosystem.jwt.service.JwtUserDetailsService;
import us.careydevelopment.util.date.DateConversionUtil;

/**
 * Helper class to determine if the user has too many failed login attempts.
 * Doesn't return anything, just throws an exception if the user failed
 * login too many times today.
 * 
 * This checks for login failures at both the IP and username levels
 */
public class LoginAttemptsUtil {

    private static final Logger LOG = LoggerFactory.getLogger(LoginAttemptsUtil.class);
    
    private static final int MAX_FAILED_LOGINS = 4;
    private static final long FAILED_LOGIN_TIMEOUT_PERIOD = DateConversionUtil.NUMBER_OF_MILLISECONDS_IN_DAY;

    
    private JwtUserDetailsService jwtUserDetailsService;
    private IpTracker ipTracker;
    
    
    public LoginAttemptsUtil(JwtUserDetailsService jwtUserDetailsService, IpTracker ipTracker) {
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.ipTracker = ipTracker;
    }
    
    
    public void checkMaxLoginAttempts(JwtRequest jwtRequest) {
        LOG.debug("Checking for too many failed logins");
        
        if (jwtRequest != null && jwtRequest.getUsername() != null) {
            BaseUser user = (BaseUser)jwtUserDetailsService.loadUserByUsername(jwtRequest.getUsername());        
            checkForFailedLogins(user);
        } else {
            throw new UserServiceAuthenticationException("Can't parse login request!");
        }
    }
    
    
    private void checkForFailedLogins(BaseUser user) {
        if (user.getFailedLoginAttempts() != null) {
            if (user.getFailedLoginAttempts() >= MAX_FAILED_LOGINS) {
                checkDateThreshold(user);
            }
        }
    }
    
    
    private void checkDateThreshold(BaseUser user) {
        if (user.getLastFailedLoginTime() != null) {
            Long now = System.currentTimeMillis();
            Long difference = now - user.getLastFailedLoginTime();
            
            if (difference < FAILED_LOGIN_TIMEOUT_PERIOD) {
                throw new TooManyFailedLoginsAuthenticationException("Too many failed logins!");
            }
        }
    }
    
    
    /**
     * Check to make sure this user hasn't failed authentication too many times
     * from the same IP address.
     */
    public void checkIpValidity(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        
        //timeframe in the past 24 hours
        Long timeframe = System.currentTimeMillis() - DateConversionUtil.NUMBER_OF_MILLISECONDS_IN_DAY;
        
        List<? extends BaseIpLog> list = ipTracker.fetchIpFailureRecord(ipAddress, timeframe);
        if (list != null && list.size() >= MAX_FAILED_LOGINS) {
            throw new TooManyFailedIpLoginsAuthenticationException("Too many failed logins from this IP address!");
        }
    }
}
