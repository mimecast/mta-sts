package com.mimecast.mtasts.client;

import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpsResponseMock implements HttpsResponse {

    private boolean successful = false;

    @Override
    public boolean isSuccessful() {
        return successful;
    }

    public HttpsResponseMock setSuccessful(boolean successful) {
        this.successful = successful;
        return this;
    }

    private int code = 0;

    @Override
    public int getCode() {
        return code;
    }

    public HttpsResponseMock setCode(int code) {
        this.code = code;
        return this;
    }

    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    public HttpsResponseMock setMessage(String message) {
        this.message = message;
        return this;
    }

    private boolean handshake = false;

    @Override
    public boolean isHandshake() {
        return handshake;
    }

    public HttpsResponseMock setHandshake(boolean handshake) {
        this.handshake = handshake;
        return this;
    }

    private List<Certificate> peerCertificates;

    @Override
    public List<Certificate> getPeerCertificates() {
        return peerCertificates;
    }

    public HttpsResponseMock setPeerCertificates(List<Certificate> peerCertificates) {
        this.peerCertificates = peerCertificates;
        return this;
    }

    private final Map<String, String> headers = new HashMap<>();

    @Override
    public String getHeader(String name) {
        return headers.get(name);
    }

    public HttpsResponseMock putHeader(String name, String value) {
        this.headers.put(name, value);
        return this;
    }

    private String body;

    @Override
    public String getBody() {
        return body;
    }

    public HttpsResponseMock setBody(String body) {
        this.body = body;
        return this;
    }
}