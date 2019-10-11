package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.util.LocalDnsResolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@SuppressWarnings("OptionalGetWithoutIsPresent")
class DnsRecordClientTest {

    @BeforeAll
    static void before() throws IOException {
        // Set local resolver
        Lookup.setDefaultResolver(new ExtendedResolver(new Resolver[]{ new LocalDnsResolver() }));
        LocalDnsResolver.put("_mta-sts.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        LocalDnsResolver.put("_mta-sts.mimecast.eu", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=;" ); }});
        LocalDnsResolver.put("_mta-sts.mimecast.us", Type.TXT, new ArrayList<String>() {{ add( "id=19840507T234501;" ); }});
    }

    @Test
    void getRecord() {
        DnsRecordClient dnsRecordClient = new XBillDnsRecordClient();
        StsRecord record = dnsRecordClient.getStsRecord("mimecast.com").get();

        assertEquals("v=STSv1; id=19840507T234501;", record.toString());
    }

    @Test
    void getInvalid() {
        DnsRecordClient dnsRecordClient = new XBillDnsRecordClient();
        Optional<StsRecord> optional = dnsRecordClient.getStsRecord("mimecast.eu");

        assertFalse(optional.get().isValid());
    }

    @Test
    void getSkipped() {
        DnsRecordClient dnsRecordClient = new XBillDnsRecordClient();
        Optional<StsRecord> optional = dnsRecordClient.getStsRecord("mimecast.us");

        assertFalse(optional.isPresent());
    }

    @Test
    void getMalformed() {
        DnsRecordClient dnsRecordClient = new XBillDnsRecordClient();
        Optional<StsRecord> optional = dnsRecordClient.getStsRecord(".eu");

        assertFalse(optional.isPresent());
    }

    @Test
    void getEmpty() {
        DnsRecordClient dnsRecordClient = new XBillDnsRecordClient();
        Optional<StsRecord> optional = dnsRecordClient.getStsRecord("mimecast.net");

        assertFalse(optional.isPresent());
    }
}
