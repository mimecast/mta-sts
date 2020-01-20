package com.mimecast.mtasts;

import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.cache.MemoryPolicyCache;
import com.mimecast.mtasts.client.XBillDnsRecordClient;
import com.mimecast.mtasts.exception.NoRecordException;
import com.mimecast.mtasts.exception.BadPolicyException;
import com.mimecast.mtasts.exception.BadRecordException;
import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.mimecast.mtasts.util.LocalDnsResolver;
import com.mimecast.mtasts.util.LocalHttpsPolicyClient;
import com.mimecast.mtasts.util.LocalHttpsResponse;
import com.mimecast.mtasts.util.LocalHttpsServer;
import org.apache.commons.validator.ValidatorException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
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
        Lookup.setDefaultResolver(new ExtendedResolver(new Resolver[]{ new LocalDnsResolver() }));
        LocalDnsResolver.put("_mta-sts.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        LocalDnsResolver.put("_smtp._tls.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com;" ); }});
        LocalDnsResolver.put("_mta-sts.mimecast.org", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        LocalDnsResolver.put("_mta-sts.mimecast.eu", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=;" ); }});
        LocalDnsResolver.put("_mta-sts.mimecast.uk", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});

        // Configure mock server
        LocalHttpsServer.put("mimecast.com", new LocalHttpsResponse()
                .setResponseString(response));

        LocalHttpsServer.put("mimecast.org", new LocalHttpsResponse());

        LocalHttpsServer.put("mimecast.uk", new LocalHttpsResponse()
                .setResponseString(response));

        // Start mock server
        localHttpsServer = new LocalHttpsServer();

        // Instanciate StrictTransportSecurity
        strictTransportSecurity = new StrictTransportSecurity(new XBillDnsRecordClient(), new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort()), new MemoryPolicyCache());
    }

    @AfterAll
    static void after() {
        localHttpsServer.stop();
    }

    @Test
    void valid() throws ValidatorException, NoRecordException, BadRecordException, BadPolicyException {
        StsPolicy policy = strictTransportSecurity.getPolicy("mimecast.com").get();

        assertEquals(response, policy.getPolicy());
        assertEquals(1, policy.getReport().getRua().size());
        assertEquals("mailto:tlsrpt@mimecast.com", policy.getReport().getRua().get(0));
    }

    @Test
    void constructor() {
        Assertions.assertThrows(InstantiationException.class, () -> new StrictTransportSecurity(null, new LocalHttpsPolicyClient(new PermissiveTrustManager(), localHttpsServer.getPort()), new MemoryPolicyCache()));
        Assertions.assertThrows(InstantiationException.class, () -> new StrictTransportSecurity(new XBillDnsRecordClient(), null, new MemoryPolicyCache()));
    }

    @Test
    void invalidDomain() {
        Assertions.assertThrows(ValidatorException.class, () -> strictTransportSecurity.getPolicy("mimecast"));
    }

    @Test
    void noDnsRecord() {
        Assertions.assertThrows(NoRecordException.class, () -> strictTransportSecurity.getPolicy("mimecast.net"));
    }

    @Test
    void invalidDnsRecord() {
        Assertions.assertThrows(BadRecordException.class, () -> strictTransportSecurity.getPolicy("mimecast.eu"));
    }

    @Test
    void invalidHttpsPolicy() {
        Assertions.assertThrows(BadPolicyException.class, () -> strictTransportSecurity.getPolicy("mimecast.org"));
    }

    @Test
    void validCache() throws ValidatorException, NoRecordException, BadRecordException, BadPolicyException {
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
    void noRecordValidCache() throws ValidatorException, NoRecordException, BadRecordException, BadPolicyException {
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
        LocalDnsResolver.put("_mta-sts.mimecast.uk", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }
}
