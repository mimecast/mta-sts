package com.mimecast.mtasts.client;

import okhttp3.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * OK HTTPS Response.
 * <p>Wrapper for HttpsPolicyClient response.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class OkHttpsResponse implements HttpsResponse {
    private static final Logger log = LogManager.getLogger(OkHttpsResponse.class);

    /**
     * OK HTTPS Response instance.
     */
    private final Response response;

    /**
     * Body string.
     */
    private String body;

    /**
     * Constructs a new HttpsResponse instance with given OK HTTP Response.
     * <p>Wrapper for OkHttpPolicyCLient response.
     *
     * @param response Response instance.
     */
    public OkHttpsResponse(Response response) throws IOException {
        this.response = response;
        body = response != null && response.body() != null ? response.body().string() : null;
    }

    /**
     * Is successful.
     *
     * @return Boolean.
     */
    @Override
    public boolean isSuccessful() {
        return response != null && response.isSuccessful();
    }

    /**
     * Gets code.
     *
     * @return Integer.
     */
    @Override
    public int getCode() {
        return response != null ? response.code() : 0;
    }

    /**
     * Gets message.
     *
     * @return Message string.
     */
    @Override
    public String getMessage() {
        return response != null ? response.message() : null;
    }

    /**
     * Is handshake.
     *
     * @return Boolean.
     */
    @Override
    public boolean isHandshake() {
        return response != null && response.handshake() != null;
    }

    /**
     * Gets peer certificates.
     *
     * @return List of Certificate.
     */
    @Override
    @SuppressWarnings("squid:S1168")
    public List<Certificate> getPeerCertificates() {
        try {
            if (response.handshake() != null) {
                return response.handshake().peerCertificates();
            }
        } catch (Exception e) {
            log.error("Found no peer certificate chain");
        }

        return new ArrayList<>();
    }

    /**
     * Gets header.
     *
     * @param name Header name string.
     * @return Header value string.
     */
    @Override
    public String getHeader(String name) {
        return response != null ? response.header(name) : null;
    }

    /**
     * Gets body.
     *
     * @return Body string.
     */
    @Override
    public String getBody() {
        return body;
    }
}
