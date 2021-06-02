package us.careydevelopment.ecosystem.jwt.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

public class CustomServletInputStream extends ServletInputStream {

    private byte[] myBytes;

    private int lastIndexRetrieved = -1;
    private ReadListener readListener = null;

    public CustomServletInputStream(String s) {
        try {
            this.myBytes = s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalStateException("JVM did not support UTF-8", ex);
        }
    }

    public CustomServletInputStream(byte[] inputBytes) {
        this.myBytes = inputBytes;
    }

    @Override
    public boolean isFinished() {
        return (lastIndexRetrieved == myBytes.length - 1);
    }

    @Override
    public boolean isReady() {
        return isFinished();
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        this.readListener = readListener;
        if (!isFinished()) {
            try {
                readListener.onDataAvailable();
            } catch (IOException e) {
                readListener.onError(e);
            }
        } else {
            try {
                readListener.onAllDataRead();
            } catch (IOException e) {
                readListener.onError(e);
            }
        }
    }

    @Override
    public int read() throws IOException {
        int i;
        if (!isFinished()) {
            i = myBytes[lastIndexRetrieved + 1];
            lastIndexRetrieved++;
            if (isFinished() && (readListener != null)) {
                try {
                    readListener.onAllDataRead();
                } catch (IOException ex) {
                    readListener.onError(ex);
                    throw ex;
                }
            }
            return i;
        } else {
            return -1;
        }
    }
};
