package com.mimecast.mtasts.util;

import com.mimecast.mtasts.client.OkHttpsPolicyClient;

import javax.net.ssl.X509TrustManager;

public class FailingHttpsPolicyClient extends OkHttpsPolicyClient {

    /**
     * HTTP server port number.
     */
    private final int port;

    /**
     * Constructs a new HttpPolicyClient instance.
     *
     * @param trustManager The trust manager instance.
     * @param port         Port number.
     */
    public FailingHttpsPolicyClient(X509TrustManager trustManager, int port) {
        super(trustManager);
        this.port = port;
    }

    /**
     * Gets URL.
     *
     * @return URL string.
     */
    @Override
    protected String getUrl(String domain) {
        return super.getUrl(domain).replace("mta-sts." + domain, "127.0.0.1:" + port).replace(".well-known/mta-sts.txt", String.valueOf(domain));
    }
}
