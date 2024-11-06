package com.mimecast.mtasts.trust;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * All trusting manager.
 * <p>Do not use this in production.
 * <p>Please provide your own trust manager implementing a trust store.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
@SuppressWarnings("all")
public class PermissiveTrustManager implements X509TrustManager {

    /**
     * Is client trusted.
     *
     * @param chain Peer certificate chain.
     * @return Boolean.
     */
    public boolean isClientTrusted(X509Certificate[] chain) {
        return true;
    }

    /**
     * Is host trusted.
     *
     * @param chain Peer certificate chain.
     * @return Boolean.
     */
    public boolean isHostTrusted(X509Certificate[] chain) {
        return true;
    }

    /**
     * Check if client is trusted.
     *
     * @param chain Peer certificate chain.
     * @param authType Key exchange algorithm used.
     * @throws CertificateException If the certificate chain is not trusted.
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // The purpose of this is to trust everything.
    }

    /**
     * Check if server is trusted.
     *
     * @param chain Peer certificate chain.
     * @param authType Key exchange algorithm used.
     * @throws CertificateException If the certificate chain is not trusted.
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // The purpose of this is to trust everything.
    }

    /**
     * Gets accepted issuers.
     *
     * @return X509Certificate array.
     */
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
