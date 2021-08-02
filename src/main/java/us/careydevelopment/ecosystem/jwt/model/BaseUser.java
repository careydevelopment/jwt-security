package us.careydevelopment.ecosystem.jwt.model;

import java.util.ArrayList;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public abstract class BaseUser implements UserDetails {

    private static final long serialVersionUID = -1838422049334585266L;

    protected String id;

    @NotBlank(message = "Please provide a username")
    @Size(max = 20, message = "Please enter a username that does not exceed 20 characters")
    protected String username;
        

    @JsonIgnore
    protected List<String> authorityNames = new ArrayList<String>();

    protected Integer failedLoginAttempts;
    protected Long lastFailedLoginTime;
    
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public List<String> getAuthorityNames() {
        return authorityNames;
    }
    
    public Integer getFailedLoginAttempts() {
        return failedLoginAttempts;
    }
    public void setFailedLoginAttempts(Integer failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }
    public Long getLastFailedLoginTime() {
        return lastFailedLoginTime;
    }
    public void setLastFailedLoginTime(Long lastFailedLoginTime) {
        this.lastFailedLoginTime = lastFailedLoginTime;
    }
    public void setAuthorityNames(List<String> authorityNames) {
        this.authorityNames = authorityNames;
    }
}
