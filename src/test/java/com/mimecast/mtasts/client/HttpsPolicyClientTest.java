package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.exception.PolicyFetchErrorException;
import com.mimecast.mtasts.exception.PolicyWebPKIInvalidException;
import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.mimecast.mtasts.util.FailingHttpsPolicyClient;
import com.mimecast.mtasts.util.LocalHttpsPolicyClient;
import com.mimecast.mtasts.util.LocalHttpsResponse;
import com.mimecast.mtasts.util.LocalHttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class HttpsPolicyClientTest {

    private static LocalHttpsServer localHttpsServer;

    private static final String valid = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: *.mimecast.com\r\n" +
            "max_age: 86400\r\n";

    private static final String malformed = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "max_age: 86400\r\n";

    private static final String oversize = valid +
            "valid: true\r\n" +
            "version: STSv1\r\n";

    @BeforeAll
    static void before() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        // Configure mock server
        LocalHttpsServer.put("mimecast.com", new LocalHttpsResponse()
                .setResponseString(valid));

        LocalHttpsServer.put("mimecast.org", new LocalHttpsResponse());

        LocalHttpsServer.put("mimecast.eu", new LocalHttpsResponse()
                .setResponseString(malformed));

        LocalHttpsServer.put("mimecast.de", new LocalHttpsResponse()
                .setResponseString(""));

        LocalHttpsServer.put("mimecast.co.uk", new LocalHttpsResponse()
                .setResponseString(oversize));

        // Start mock server
        localHttpsServer = new LocalHttpsServer();
    }

    @AfterAll
    static void after() {
        localHttpsServer.stop();
    }

    @Test
    @DisplayName("should validate valid MTA-STS responses")
    void valid() throws Exception {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        HttpsResponse httpsResponse = httpsPolicyClient.getPolicy(record, 64000);

        assertTrue(httpsResponse.isSuccessful());
        assertEquals(200, httpsResponse.getCode());
        assertEquals("OK", httpsResponse.getMessage());
        assertTrue(httpsResponse.isHandshake());
        assertEquals(0, httpsResponse.getPeerCertificates().size());
        assertEquals("text/plain", httpsResponse.getHeader("Content-Type"));
        assertEquals(valid, httpsResponse.getBody());
    }

    @Test
    @DisplayName("should return a 404 error for MTA-STS policies that cannot be found")
    void invalidNone() throws Exception {
        StsRecord record = new StsRecord("mimecast.net", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        HttpsResponse httpsResponse = httpsPolicyClient.getPolicy(record, 64000);

        assertFalse(httpsResponse.isSuccessful());
        assertEquals(404, httpsResponse.getCode());
        assertEquals("Not Found", httpsResponse.getMessage());
        assertTrue(httpsResponse.isHandshake());
        assertEquals(0, httpsResponse.getPeerCertificates().size());
        assertEquals("text/html", httpsResponse.getHeader("Content-Type"));
        assertEquals("<h1>404 Not Found</h1>No context found for request", httpsResponse.getBody());
    }

    @Test
    @DisplayName("should return a 404 error for MTA-STS policies that return no content")
    void invalidNull() throws Exception {
        StsRecord record = new StsRecord("mimecast.org", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        HttpsResponse httpsResponse = httpsPolicyClient.getPolicy(record, 64000);

        assertFalse(httpsResponse.isSuccessful());
        assertEquals(404, httpsResponse.getCode());
        assertEquals("Not Found", httpsResponse.getMessage());
        assertTrue(httpsResponse.isHandshake());
        assertEquals(0, httpsResponse.getPeerCertificates().size());
        assertNull(httpsResponse.getHeader("Content-Type"));
        assertEquals("", httpsResponse.getBody());
    }

    @Test
    @DisplayName("should return empty content for empty MTA-STS policies")
    void invalidEmpty() throws Exception {
        StsRecord record = new StsRecord("mimecast.de", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        HttpsResponse httpsResponse = httpsPolicyClient.getPolicy(record, 64000);

        assertTrue(httpsResponse.isSuccessful());
        assertEquals(200, httpsResponse.getCode());
        assertEquals("OK", httpsResponse.getMessage());
        assertTrue(httpsResponse.isHandshake());
        assertEquals(0, httpsResponse.getPeerCertificates().size());
        assertEquals("text/plain", httpsResponse.getHeader("Content-Type"));
        assertEquals("", httpsResponse.getBody());
    }

    @Test
    @DisplayName("should truncate oversized MTA-STS response bodies so that they are under the maximum policy body size")
    void oversizedResponseBody() throws Exception {
        final int maxPolicyBodySize = 90; // Reducing the maximum policy body size to 90 for ease of testing.
        StsRecord record = new StsRecord("mimecast.co.uk", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        HttpsResponse httpsResponse = httpsPolicyClient.getPolicy(record, maxPolicyBodySize);
        assertTrue(httpsResponse.isSuccessful());
        assertEquals(200, httpsResponse.getCode());
        assertEquals("OK", httpsResponse.getMessage());
        assertTrue(httpsResponse.isHandshake());
        assertEquals(0, httpsResponse.getPeerCertificates().size());
        assertEquals("text/plain", httpsResponse.getHeader("Content-Type"));
        assertTrue(httpsResponse.getBody().length() <= maxPolicyBodySize);
    }

    @Test
    @DisplayName("should invalidate null records")
    void invalidNullRecord() throws Exception {
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertNull(httpsPolicyClient.getPolicy(null, 64000));
    }

    @Test
    @DisplayName("should invalidate null domains")
    void invalidNullDomain() throws Exception {
        StsRecord record = new StsRecord(null, "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertNull(httpsPolicyClient.getPolicy(record, 64000));
    }

    @Test
    @DisplayName("throw error for webpki invalid host")
    void exceptionWhenWebPKIInvalidHost() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) { }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("PKIX path validation failed");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }, localHttpsServer.getPort());

        assertThrows(PolicyWebPKIInvalidException.class, () -> httpsPolicyClient.getPolicy(record, 6400));
    }

    @Test
    @DisplayName("throw error for failed host")
    void exceptionWhenFailedHost() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new FailingHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertThrows(PolicyFetchErrorException.class, () -> httpsPolicyClient.getPolicy(record, 6400));
    }
}
