package us.careydevelopment.ecosystem.jwt.model;

public abstract class BaseIpLog {

    protected String ipAddress;
    protected String username;
    protected Long lastLoginAttempt;
    protected Boolean successfulLogin;
    
    public String getIpAddress() {
        return ipAddress;
    }
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public Long getLastLoginAttempt() {
        return lastLoginAttempt;
    }
    public void setLastLoginAttempt(Long lastLoginAttempt) {
        this.lastLoginAttempt = lastLoginAttempt;
    }
    public Boolean getSuccessfulLogin() {
        return successfulLogin;
    }
    public void setSuccessfulLogin(Boolean successfulLogin) {
        this.successfulLogin = successfulLogin;
    }
}
