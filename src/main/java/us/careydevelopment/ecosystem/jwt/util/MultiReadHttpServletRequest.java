package us.careydevelopment.ecosystem.jwt.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This exists because we need to read contents of the request body
 * at multiple points in the filter chain.
 */
public class MultiReadHttpServletRequest extends  HttpServletRequestWrapper {

    private String body;

    
    public MultiReadHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        body = "";
        BufferedReader bufferedReader = request.getReader();           
        String line;
        while ((line = bufferedReader.readLine()) != null){
            body += line;
        }
    }

    
    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
        return new CustomServletInputStream(byteArrayInputStream.readAllBytes());
    }

    
    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(this.getInputStream()));
    }
}
