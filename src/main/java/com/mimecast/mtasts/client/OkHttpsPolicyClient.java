package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.assets.StsRecord;
import okhttp3.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Ok Https Policy Client.
 * <p>HTTPS client implemenation specific for MTA-STS.
 *
 * @link https://tools.ietf.org/html/rfc8461#section-3.3 RFC8461#section-3.3
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class OkHttpsPolicyClient implements HttpsPolicyClient {
    private static final Logger log = LogManager.getLogger(OkHttpsPolicyClient.class);

    /**
     * Trust manager to use for certificate validation.
     */
    private final X509TrustManager trustManager;

    /**
     * HTTPS connection timeout.
     */
    private static int connectTimeout = 10;

    /**
     * HTTPS write timeout.
     */
    private static int writeTimeout = 10;

    /**
     * HTTPS read timeout.
     */
    private static int readTimeout = 10;

    /**
     * Constructs a new HttpPolicyClient instance.
     *
     * @param trustManager X509TrustManager instance.
     */
    public OkHttpsPolicyClient(X509TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    /**
     * Gets policy.
     * <p>Requires a fresh StsRecord instance to get the domain from and construct the StsPolicy instance.
     * <p>Will only return valid and not expired policies.
     *
     * @param record StsRecord instance.
     * @return Optional of StsPolicy instance.
     */
    @Override
    public Optional<StsPolicy> getPolicy(StsRecord record) {
        if (record != null) {
            try {
                // Request
                Request request = new Request.Builder()
                        .url(getUrl(record.getDomain()))
                        .addHeader("Content-Type", "text/plain")
                        .addHeader("Cache-Control", "no-cache")
                        .build();

                // Response
                Response response = getClient().newCall(request).execute();
                ResponseBody body = response.body();

                // Success
                if (response.isSuccessful() && response.code() == 200 && response.handshake() != null && body != null &&
                        Objects.equals(response.header("Content-Type"), "text/plain")) {

                    StsPolicy policy = new StsPolicy(record, body.string());
                    setPeerCertificates(response, policy);

                    // Return only if valid
                    if (policy.isValid()) {
                        return Optional.of(policy);
                    }
                    else {
                        log.warn("Policy retrieved but invalid");
                    }
                }
                else {
                    log.error("Response error: {}", response.message());
                }

            } catch (GeneralSecurityException | IOException e) {
                log.error("Unable to retrieve policy: {}", e.getMessage());
            }
        }

        return Optional.empty();
    }

    /**
     * Sets peer certificate chain or tries to.
     * <p>Capture and log error signaling connection was not secure (testing).
     *
     * @param response Response instance.
     * @param policy   StsPolicy instance.
     */
    private void setPeerCertificates(Response response, StsPolicy policy) {
        try {
            if (response.handshake() != null) {
                policy.setPeerCertificates(response.handshake().peerCertificates());
            }
        } catch (Exception e) {
            log.error("Found no peer certificate chain");
        }
    }

    /**
     * Gets URL.
     * <p>Isolated for testing.
     *
     * @param domain Domain string.
     * @return URL string.
     */
    protected String getUrl(String domain) {
        return "https://mta-sts." + domain + "/.well-known/mta-sts.txt";
    }

    /**
     * Gets OkHttpClient.
     *
     * @return OkHttpClient instance.
     * @throws KeyManagementException   Key management exception.
     * @throws NoSuchAlgorithmException No such algorithm exception.
     */
    private OkHttpClient getClient() throws KeyManagementException, NoSuchAlgorithmException {
        // Client
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        return getBuilder(socketFactory).build();
    }

    /**
     * Gets OkHttpClient.Builder.
     * <p>Isolated for testing.
     * <p>Disabled redirects per RFC specification.
     *
     * @param socketFactory SSLSocketFactory instance.
     * @return OkHttpClient.Builder instance.
     */
    protected OkHttpClient.Builder getBuilder(SSLSocketFactory socketFactory) {
        return new OkHttpClient.Builder()
                .addInterceptor(new UserAgentInterceptor())
                .connectTimeout(connectTimeout, TimeUnit.SECONDS)
                .writeTimeout(writeTimeout, TimeUnit.SECONDS)
                .readTimeout(readTimeout, TimeUnit.SECONDS)
                .sslSocketFactory(socketFactory, trustManager)
                .followRedirects(false)
                .followSslRedirects(false);
    }

    /**
     * Sets connection timeout.
     *
     * @param seconds Integer.
     */
    public static void setConnectTimeout(int seconds) {
        connectTimeout = seconds;
    }

    /**
     * Sets write timeout.
     *
     * @param seconds Integer.
     */
    public static void setWriteTimeout(int seconds) {
        writeTimeout = seconds;
    }

    /**
     * Sets read timeout.
     *
     * @param seconds Integer.
     */
    public static void setReadTimeout(int seconds) {
        readTimeout = seconds;
    }

    /**
     * Transforms User-Agent header on the request.
     */
    static class UserAgentInterceptor implements Interceptor {

        /**
         * Intercepts request and modifies User-Agent header.
         *
         * @param chain Chain instance.
         * @return Response instance.
         * @throws IOException IO exception.
         */
        @NotNull
        @Override
        public Response intercept(@NotNull Chain chain) throws IOException {
            Request request = chain.request().newBuilder().header("User-Agent", "Mimecast MTA-STS").build();
            return chain.proceed(request);
        }
    }
}
