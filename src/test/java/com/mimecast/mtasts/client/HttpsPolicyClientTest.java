package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.mimecast.mtasts.util.LocalHttpsPolicyClient;
import com.mimecast.mtasts.util.LocalHttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class HttpsPolicyClientTest {

    private static LocalHttpsServer localHttpsServer;

    private static final String valid = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: service-alpha-inbound-*.mimecast.com\r\n" +
            "max_age: 86400\r\n";

    private static final String malformed = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "max_age: 86400\r\n";

    @BeforeAll
    static void before() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        // Configure mock server
        LocalHttpsServer.put("mimecast.com", valid);
        LocalHttpsServer.put("mimecast.org", null);
        LocalHttpsServer.put("mimecast.eu", malformed);

        // Start mock server
        localHttpsServer = new LocalHttpsServer();
    }

    @AfterAll
    static void after() {
        localHttpsServer.stop();
    }

    @Test
    void valid() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertEquals(valid, httpsPolicyClient.getPolicy(record).get().toString());
    }

    @Test
    void invalid() {
        StsRecord record = new StsRecord("mimecast.net", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertFalse(httpsPolicyClient.getPolicy(record).isPresent());
    }

    @Test
    void invalidNull() {
        StsRecord record = new StsRecord("mimecast.org", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertFalse(httpsPolicyClient.getPolicy(record).isPresent());
    }

    @Test
    void invalidMalformed() {
        StsRecord record = new StsRecord("mimecast.eu", "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertFalse(httpsPolicyClient.getPolicy(record).isPresent());
    }

    @Test
    void invalidNullRecord() {
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertFalse(httpsPolicyClient.getPolicy(null).isPresent());
    }

    @Test
    void invalidNullDomain() {
        StsRecord record = new StsRecord(null, "\"v=STSv1; id=19840507T234501;\"");
        HttpsPolicyClient httpsPolicyClient = new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());

        assertFalse(httpsPolicyClient.getPolicy(record).isPresent());
    }
}
