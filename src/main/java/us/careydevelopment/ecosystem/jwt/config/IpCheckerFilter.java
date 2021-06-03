package us.careydevelopment.ecosystem.jwt.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import us.careydevelopment.util.api.response.ResponseUtil;

/**
 * This class makes sure the requests come to us from an allowed IP address
 * 
 * Note: this class does NOT check for max failed login attempts from a single IP address.
 * That occurs in CredentialsAuthenticationFilter with the help of IpTracker.
 * 
 * Going this route instead of doing the CORS thing because in a Kubernetes cluster each
 * request gets a new port. That makes it difficult (to say the least) to define valid
 * origins.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class IpCheckerFilter extends OncePerRequestFilter {
    
    private static final String ALLOWED_ORIGIN = "https://bixis.us";
    
    private static final Logger LOG = LoggerFactory.getLogger(IpCheckerFilter.class);
   
    private List<String> ipWhitelist = new ArrayList<>();
    private String privateIp = "0.0.0.6";
    
    
    public IpCheckerFilter(@Value("${ip.whitelist}") String[] ipWhitelist, @Value("${private.ip}") String privateIp) {
        if (ipWhitelist != null) this.ipWhitelist = List.of(ipWhitelist);
        this.privateIp = privateIp;
    }

    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {

        boolean proceed = true;
        String header = request.getHeader(HttpHeaders.ORIGIN);
        
        if (!ALLOWED_ORIGIN.equals(header)) {
            String ipAddress = request.getRemoteAddr();
            LOG.debug("Remote IP address is " + ipAddress);
          
            if (ipAddress != null) {
                //necessary for pod-to-pod communication
                if (!ipAddress.startsWith(privateIp)) {
                    if (!ipWhitelist.contains(ipAddress)) {
                        proceed = false;                
                    }
                }
            } else {
                proceed = false;
            }
        }
      
        if (!proceed) {
            ResponseUtil.badOrigin(response);
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
