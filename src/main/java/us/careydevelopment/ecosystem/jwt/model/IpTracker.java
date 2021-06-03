package us.careydevelopment.ecosystem.jwt.model;

import java.util.List;

import us.careydevelopment.ecosystem.jwt.model.BaseIpLog;

/**
 * This gets implemented in the Spring Boot application
 *
 * Basically, it defines callbacks for IP tracking to boot out people who try too many failed
 * login attempts from the same IP address.
 * 
 * But it also defines methods for recording all IP access, successful or otherwise 
 */
public interface IpTracker {

    /**
     * Looks for failed login attempts later than or equal to the starting time.
     * 
     * Note that the startingTime is the number of milliseconds since 1970 began.
     * 
     * @param ipAddress
     * @param startingTime
     * @return a list of IP log records representing failed login attempts
     */
    public List<? extends BaseIpLog> fetchIpFailureRecord(String ipAddress, Long startingTime);
    

    /**
     * Logs a successful authentication from the given IP address
     * 
     * @param username
     * @param ipAddress
     */
    public void successfulLogin(String username, String ipAddress);
    
    
    /**
     * Logs an unsuccessful authentication from the given IP address
     * 
     * @param username
     * @param ipAddress
     */
    public void unsuccessfulLogin(String username, String ipAddress);
}
