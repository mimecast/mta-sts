package com.mimecast.mtasts;

import com.google.gson.Gson;
import com.mimecast.mtasts.util.LocalDnsResolver;
import com.mimecast.mtasts.util.LocalHttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MainTest {

    private static LocalHttpsServer localHttpsServer;

    private static final String response = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: service-alpha-inbound-*.mimecast.com\r\n" +
            "max_age: 86400\r\n";

    @BeforeAll
    static void before() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        // Set local resolver
        Lookup.setDefaultResolver(new ExtendedResolver(new Resolver[]{ new LocalDnsResolver() }));
        LocalDnsResolver.put("_mta-sts.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=STSv1; id=19840507T234501;" ); }});
        LocalDnsResolver.put("_smtp._tls.mimecast.com", Type.TXT, new ArrayList<String>() {{ add( "v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com;" ); }});
        LocalDnsResolver.put("mimecast.com", Type.MX, new ArrayList<String>() {{
            add("service-alpha-inbound-a.mimecast.com.");
            add("service-alpha-inbound-b.mimecast.com.");
        }});

        // Configure mock server
        LocalHttpsServer.put("mimecast.com", response);

        // Start mock server
        localHttpsServer = new LocalHttpsServer();
    }

    @AfterAll
    static void after() {
        localHttpsServer.stop();
    }

    @Test
    void nullArgs() throws InstantiationException {
        List<String> logs = MainMock.main(null, localHttpsServer.getPort());

        assertEquals("java -jar mta-sts.jar", logs.get(0));
        assertEquals(" SMTP MTA Strict Transport Security", logs.get(1));
        assertEquals("", logs.get(2));
        assertEquals("usage:   [-d <arg>] [-f <arg>] [-j] [-m <arg>]\n" +
                " -d,--domain <arg>   Domain\n" +
                " -f,--file <arg>     Write policy details to JSON file\n" +
                " -j,--json           Show policy details as JSON\n" +
                " -m,--mx <arg>       MX to match against policy MX masks\n", logs.get(3));
        assertEquals("", logs.get(4));
    }

    @Test
    void noArgs() throws InstantiationException {
        List<String> logs = MainMock.main(new String[0], localHttpsServer.getPort());

        assertEquals("java -jar mta-sts.jar", logs.get(0));
        assertEquals(" SMTP MTA Strict Transport Security", logs.get(1));
        assertEquals("", logs.get(2));
        assertEquals("usage:   [-d <arg>] [-f <arg>] [-j] [-m <arg>]\n" +
                " -d,--domain <arg>   Domain\n" +
                " -f,--file <arg>     Write policy details to JSON file\n" +
                " -j,--json           Show policy details as JSON\n" +
                " -m,--mx <arg>       MX to match against policy MX masks\n", logs.get(3));
        assertEquals("", logs.get(4));
    }

    @Test
    void badArgs() throws InstantiationException {
        List<String> argv = new ArrayList<>();

        argv.add("-b");
        argv.add("Bad");

        List<String> logs = MainMock.main(argv.toArray(new String[0]), localHttpsServer.getPort());

        assertEquals("java -jar mta-sts.jar", logs.get(0));
        assertEquals(" SMTP MTA Strict Transport Security", logs.get(1));
        assertEquals("", logs.get(2));
        assertEquals("usage:   [-d <arg>] [-f <arg>] [-j] [-m <arg>]\n" +
                " -d,--domain <arg>   Domain\n" +
                " -f,--file <arg>     Write policy details to JSON file\n" +
                " -j,--json           Show policy details as JSON\n" +
                " -m,--mx <arg>       MX to match against policy MX masks\n", logs.get(3));
        assertEquals("", logs.get(4));
    }

    @Test
    void shortArgs() throws InstantiationException {
        List<String> argv = new ArrayList<>();

        argv.add("-d");
        argv.add("mimecast.com");
        argv.add("-m");
        argv.add("service-alpha-inbound-a.mimecast.com");
        argv.add("-j");

        List<String> logs = MainMock.main(argv.toArray(new String[0]), localHttpsServer.getPort());

        assertEquals("Match MX", logs.get(0));
        assertEquals("MX:\t\tservice-alpha-inbound-a.mimecast.com", logs.get(2));
        assertEquals("Match:\ttrue", logs.get(3));

        Map expected = new Gson().fromJson("{\"stsPolicy\":{\"mode\":\"enforce\",\"max_age\":\"604800\",\"valid\":\"true\",\"mx\":\"service-alpha-inbound-*.mimecast.com\",\"version\":\"STSv1\"},\"tlsRecord\":{\"valid\":\"true\",\"version\":\"TLSRPTv1\",\"rua\":\"mailto:tlsrpt@mimecast.com\"},\"mxList\":[{\"entry\":\"service-alpha-inbound-a.mimecast.com\",\"priority\":\"1\"},{\"entry\":\"service-alpha-inbound-b.mimecast.com\",\"priority\":\"1\"}],\"stsRecord\":{\"valid\":\"true\",\"location\":\"_mta-sts.mimecast.com\",\"id\":\"19840507T234501\",\"version\":\"STSv1\"}}", Map.class);
        Map actual = new Gson().fromJson(logs.get(5), Map.class);
        assertEquals(expected, actual);
    }

    @Test
    void longArgs() throws InstantiationException {
        List<String> argv = new ArrayList<>();

        argv.add("--domain");
        argv.add("mimecast.com");
        argv.add("--mx");
        argv.add("service-alpha-inbound-a.mimecast.com");

        List<String> logs = MainMock.main(argv.toArray(new String[0]), localHttpsServer.getPort());

        assertEquals("Match MX", logs.get(0));
        assertEquals("MX:\t\tservice-alpha-inbound-a.mimecast.com", logs.get(2));
        assertEquals("Match:\ttrue", logs.get(3));
    }

    @Test
    void noMatch() throws InstantiationException {
        List<String> argv = new ArrayList<>();

        argv.add("--domain");
        argv.add("mimecast.com");
        argv.add("--mx");
        argv.add("service-alpha-a.mimecast.com");

        List<String> logs = MainMock.main(argv.toArray(new String[0]), localHttpsServer.getPort());

        assertEquals("Match MX", logs.get(0));
        assertEquals("MX:\t\tservice-alpha-a.mimecast.com", logs.get(2));
        assertEquals("Match:\tfalse", logs.get(3));
    }
}