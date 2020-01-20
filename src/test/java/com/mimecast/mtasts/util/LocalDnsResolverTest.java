package com.mimecast.mtasts.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;

import java.io.IOException;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class LocalDnsResolverTest {

    @BeforeAll
    static void before() throws IOException {
        // Set local resolver
        Lookup.setDefaultResolver(new ExtendedResolver(new Resolver[]{ new LocalDnsResolver() }));

        // Valid && supported
        LocalDnsResolver.put("mimecast.com", Type.NS, new ArrayList<String>() {{
            add("dns01.mimecast.com.");
            add("dns02.mimecast.com.");
            add("dns03.mimecast.com.");
            add("dns04.mimecast.com.");
        }});

        LocalDnsResolver.put("mimecast.com", Type.MX, new ArrayList<String>() {{
            add("service-alpha-inbound-a.mimecast.com.");
            add("service-alpha-inbound-b.mimecast.com.");
        }});

        LocalDnsResolver.put("service-alpha-inbound-a.mimecast.com", Type.A, new ArrayList<String>() {{
            add("91.220.42.231");
        }});

        LocalDnsResolver.put("service-alpha-inbound-b.mimecast.com", Type.A, new ArrayList<String>() {{
            add("195.130.217.231");
        }});

        LocalDnsResolver.put("91.220.42.231", Type.PTR, new ArrayList<String>() {{
            add("service-alpha-inbound-a.mimecast.com.");
        }});

        LocalDnsResolver.put("195.130.217.231", Type.PTR, new ArrayList<String>() {{
            add("service-alpha-inbound-b.mimecast.com.");
        }});

        LocalDnsResolver.put("_mta-sts.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        LocalDnsResolver.put("_smtp._tls.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com;" ); }});

        // Invalid || unsupported
        LocalDnsResolver.put("mimecast.com", Type.AAAA, new ArrayList<String>() {{
            add("::1");
        }});

        LocalDnsResolver.put("mimecast.eu", Type.A, new ArrayList<String>() {{
            add("a.b.c.d");
        }});
        LocalDnsResolver.put("mimecast.eu", Type.MX, new ArrayList<String>() {{
            add("");
        }});
    }

    @Test
    void valid() throws TextParseException {
        assertTrue(lookup("mimecast.com.", Type.NS)[0].rdataToString().matches("^dns0[0-9]\\.mimecast\\.com\\.$"));
        assertTrue(lookup("mimecast.com.", Type.NS)[1].rdataToString().matches("^dns0[0-9]\\.mimecast\\.com\\.$"));
        assertTrue(lookup("mimecast.com.", Type.NS)[2].rdataToString().matches("^dns0[0-9]\\.mimecast\\.com\\.$"));
        assertTrue(lookup("mimecast.com.", Type.NS)[3].rdataToString().matches("^dns0[0-9]\\.mimecast\\.com\\.$"));

        assertTrue(lookup("mimecast.com.", Type.MX)[0].rdataToString().matches("^1 service-alpha-inbound-[ab]\\.mimecast\\.com\\.$"));
        assertTrue(lookup("mimecast.com.", Type.MX)[1].rdataToString().matches("^1 service-alpha-inbound-[ab]\\.mimecast\\.com\\.$"));

        assertEquals("91.220.42.231", lookup("service-alpha-inbound-a.mimecast.com", Type.A)[0].rdataToString());
        assertEquals("195.130.217.231", lookup("service-alpha-inbound-b.mimecast.com", Type.A)[0].rdataToString());

        assertEquals("\"v=STSv1; id=19840507T234501;\"", lookup("_mta-sts.mimecast.com", Type.TXT)[0].rdataToString());
        assertEquals("\"v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com;\"", lookup("_smtp._tls.mimecast.com", Type.TXT)[0].rdataToString());

        assertEquals("service-alpha-inbound-a.mimecast.com.", lookup("91.220.42.231", Type.PTR)[0].rdataToString());
        assertEquals("service-alpha-inbound-b.mimecast.com.", lookup("195.130.217.231", Type.PTR)[0].rdataToString());
    }

    @Test
    void invalid() throws TextParseException {
        Assertions.assertThrows(IllegalArgumentException.class, () -> lookup("mimecast.com", Type.AAAA));

        assertNull(lookup("mimecast.org", Type.A));
        assertNull(lookup("mimecast.net", Type.A));
        assertNull(lookup("mimecast.eu", Type.A));
        assertNull(lookup("mimecast.eu", Type.MX));
    }

    Record[] lookup(String uri, int type) throws TextParseException {
        Lookup lookup = new Lookup(uri, type);
        return lookup.run();
    }
}
