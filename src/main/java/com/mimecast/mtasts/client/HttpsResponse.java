package com.mimecast.mtasts.client;

import java.security.cert.Certificate;
import java.util.List;

/**
 * HTTPS Response Interface.
 * <p>Wrapper for HttpPolicyClient response.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http ://mimecast.com Mimecast
 */
public interface HttpsResponse {

    /**
     * Is successful.
     *
     * @return Boolean.
     */
    boolean isSuccessful();

    /**
     * Gets code.
     *
     * @return Integer.
     */
    int getCode();

    /**
     * Gets message.
     *
     * @return Message string.
     */
    String getMessage();

    /**
     * Is handshake.
     *
     * @return Boolean.
     */
    boolean isHandshake();

    /**
     * Gets peer certificates.
     *
     * @return List of Certificate.
     */
    List<Certificate> getPeerCertificates();

    /**
     * Gets header.
     *
     * @param name Header name string.
     * @return the header
     */
    String getHeader(String name);

    /**
     * Gets body.
     *
     * @return Body string.
     */
    String getBody();
}
