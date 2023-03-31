package com.mimecast.mtasts;

import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.cache.MemoryPolicyCache;
import com.mimecast.mtasts.client.HttpsPolicyClient;
import com.mimecast.mtasts.client.XBillDnsRecordClient;
import com.mimecast.mtasts.exception.*;
import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.mimecast.mtasts.util.*;
import org.apache.commons.validator.ValidatorException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Type;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class StrictTransportSecurityTest {

    private static LocalHttpsServer localHttpsServer;
    private static StrictTransportSecurity strictTransportSecurity;

    private static final String response = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: *.mimecast.com\r\n" +
            "max_age: 86400\r\n";

    @BeforeAll
    static void before() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException, InstantiationException {
        // Set local resolver
        Lookup.setDefaultResolver(new LocalDnsResolver());
        LocalDnsResolver.put("_mta-sts.mimecast.com", Type.TXT, new ArrayList<String>() {{
            add("v=STSv1; id=19840507T234501;");
        }});
        LocalDnsResolver.put("_smtp._tls.mimecast.com", Type.TXT, new ArrayList<String>() {{
            add("v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com;");
        }});
        LocalDnsResolver.put("_mta-sts.mimecast.org", Type.TXT, new ArrayList<String>() {{
            add("v=STSv1; id=19840507T234501;");
        }});
        LocalDnsResolver.put("_mta-sts.mimecast.eu", Type.TXT, new ArrayList<String>() {{
            add("v=STSv1; id=;");
        }});
        LocalDnsResolver.put("_mta-sts.mimecast.uk", Type.TXT, new ArrayList<String>() {{
            add("v=STSv1; id=19840507T234501;");
        }});

        // Configure mock server
        LocalHttpsServer.put("mimecast.com", new LocalHttpsResponse()
                .setResponseString(response));

        LocalHttpsServer.put("mimecast.org", new LocalHttpsResponse());

        LocalHttpsServer.put("mimecast.uk", new LocalHttpsResponse()
                .setResponseString(response));

        // Start mock server
        localHttpsServer = new LocalHttpsServer();

        // Instantiate StrictTransportSecurity
        strictTransportSecurity = new StrictTransportSecurity(new XBillDnsRecordClient(), new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort()), new MemoryPolicyCache());
    }

    @AfterAll
    static void after() {
        localHttpsServer.stop();
    }

    @Test
    void valid() throws Exception {
        StsPolicy policy = strictTransportSecurity.getPolicy("mimecast.com").get();

        assertEquals(response, policy.getPolicy());
        assertEquals(1, policy.getReport().getRua().size());
        assertEquals("mailto:tlsrpt@mimecast.com", policy.getReport().getRua().get(0));
    }

    @Test
    void constructor() {
        assertThrows(InstantiationException.class, () -> new StrictTransportSecurity(null, new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort()), new MemoryPolicyCache()));
        assertThrows(InstantiationException.class, () -> new StrictTransportSecurity(new XBillDnsRecordClient(), null, new MemoryPolicyCache()));
    }

    @Test
    void invalidDomain() {
        assertThrows(ValidatorException.class, () -> strictTransportSecurity.getPolicy("mimecast"));
    }

    @Test
    void noDnsRecord() {
        assertThrows(NoRecordException.class, () -> strictTransportSecurity.getPolicy("mimecast.net"));
    }

    @Test
    void invalidDnsRecord() {
        assertThrows(BadRecordException.class, () -> strictTransportSecurity.getPolicy("mimecast.eu"));
    }

    @Test
    void invalidPolicyWebPKIException() throws InstantiationException {
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

        StrictTransportSecurity invalidPolicyStrictTransportSecurity = new StrictTransportSecurity(new XBillDnsRecordClient(), httpsPolicyClient);
        assertThrows(PolicyWebPKIInvalidException.class, () -> invalidPolicyStrictTransportSecurity.getPolicy("mimecast.com"));
    }

    @Test
    void policyFetchErrorException() throws InstantiationException {
        FailingHttpsPolicyClient failingHttpsPolicyClient  = new FailingHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort());
        StrictTransportSecurity fetchErrorStrictTransportSecurity = new StrictTransportSecurity(new XBillDnsRecordClient(), failingHttpsPolicyClient);
        assertThrows(PolicyFetchErrorException.class, () -> fetchErrorStrictTransportSecurity.getPolicy("mimecast.com"));
    }

    @Test
    void invalidHttpsPolicy() {
        assertThrows(BadPolicyException.class, () -> strictTransportSecurity.getPolicy("mimecast.org"));
    }

    @Test
    void validCache() throws Exception {
        StsPolicy policy;

        // Ensure cached
        policy = strictTransportSecurity.getPolicy("mimecast.com").get();
        assertEquals(response, policy.getPolicy());

        // Check cached
        policy = strictTransportSecurity.getPolicy("mimecast.com").get();
        assertEquals(response, policy.getPolicy());
        assertTrue(policy.isCached());
    }

    @Test
    void noRecordValidCache() throws Exception {
        StsPolicy policy;

        // Ensure cached
        policy = strictTransportSecurity.getPolicy("mimecast.uk").get();
        assertEquals(response, policy.getPolicy());

        // Remove from resolver
        LocalDnsResolver.put("_mta-sts.mimecast.uk", Type.TXT, new ArrayList<>());
        Lookup.getDefaultCache(DClass.IN).clearCache();

        // Check cached
        policy = strictTransportSecurity.getPolicy("mimecast.uk").get();
        assertEquals(response, policy.getPolicy());
        assertTrue(policy.isCached());

        // Put back into resolver
        LocalDnsResolver.put("_mta-sts.mimecast.uk", Type.TXT, new ArrayList<String>() {{
            add("v=STSv1; id=19840507T234501;");
        }});
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }
}
