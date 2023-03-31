package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.config.Config;
import com.mimecast.mtasts.config.ConfigHandler;
import com.mimecast.mtasts.exception.PolicyFetchErrorException;
import com.mimecast.mtasts.exception.PolicyWebPKIInvalidException;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

/**
 * OK HTTPS Policy Client.
 * <p>HTTPS client implementation specific for MTA-STS.
 *
 * @link <a href="https://tools.ietf.org/html/rfc8461#section-3.3">RFC8461#section-3.3</a>
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public class OkHttpsPolicyClient extends ConfigHandler implements HttpsPolicyClient {

    /**
     * Trust manager to use for certificate validation.
     */
    private final X509TrustManager trustManager;

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
     * @param stsRecord StsRecord instance.
     * @param maxPolicyBodySize The maximum size of the policy body.
     * @return OkHttpsResponse instance.
     * @throws PolicyWebPKIInvalidException Policy web PKI invalid exception.
     * @throws PolicyFetchErrorException Policy fetch error exception.
     */
    @Override
    public OkHttpsResponse getPolicy(StsRecord stsRecord, int maxPolicyBodySize) throws PolicyWebPKIInvalidException, PolicyFetchErrorException {
        if (maxPolicyBodySize == 0) {
            // Default to the maximum policy body size specified in the config (64k) if it is zero or not present.
            maxPolicyBodySize = new Config().getPolicyMaxBodySize();
        }

        if (stsRecord != null && stsRecord.getDomain() != null) {
            try {
                // Request.
                Request request = new Request.Builder()
                        .url(getUrl(stsRecord.getDomain()))
                        .addHeader("Content-Type", "text/plain")
                        .addHeader("Cache-Control", "no-cache")
                        .build();

                // Response.
                Response response = getClient().newCall(request).execute();

                // Extract data.
                OkHttpsResponse okHttpsResponse = new OkHttpsResponse(response, maxPolicyBodySize);
                response.close();

                return okHttpsResponse;
            } catch (SSLHandshakeException e) {
                throw new PolicyWebPKIInvalidException(e.getMessage());
            } catch (Exception e) {
                throw new PolicyFetchErrorException(e.getMessage());
            }
        }

        return null;
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
        // Client.
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
                .connectTimeout(config.getConnectTimeout(), TimeUnit.SECONDS)
                .writeTimeout(config.getWriteTimeout(), TimeUnit.SECONDS)
                .readTimeout(config.getReadTimeout(), TimeUnit.SECONDS)
                .sslSocketFactory(socketFactory, trustManager)
                .followRedirects(false)
                .followSslRedirects(false);
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
