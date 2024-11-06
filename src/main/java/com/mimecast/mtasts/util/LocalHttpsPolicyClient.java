package com.mimecast.mtasts.util;

import com.mimecast.mtasts.client.OkHttpsPolicyClient;
import okhttp3.OkHttpClient;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Local Https Policy Client.
 * <p>Extends HttpsPolicyClient to mock resources needed for testing via local server.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
@SuppressWarnings("squid:S3510")
public class LocalHttpsPolicyClient extends OkHttpsPolicyClient {

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
    public LocalHttpsPolicyClient(X509TrustManager trustManager, int port) {
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

    /**
     * Gets OkHttpClient.Builder.
     *
     * @param socketFactory SSLSocketFactory instance.
     * @return OkHttpClient.Builder instance.
     */
    @Override
    protected OkHttpClient.Builder getBuilder(SSLSocketFactory socketFactory) {
        return super.getBuilder(socketFactory).hostnameVerifier((hostname, session) -> true);
    }
}
