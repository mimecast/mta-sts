package com.mimecast.mtasts;

import com.google.gson.Gson;
import com.mimecast.mtasts.util.LocalDnsResolver;
import com.mimecast.mtasts.util.LocalHttpsResponse;
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
            "mx: *.mimecast.com\r\n" +
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
        LocalHttpsServer.put("mimecast.com", new LocalHttpsResponse()
                .setResponseString(response));

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
    @SuppressWarnings("unchecked")
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

        String expected = "{\n" +
                "  \"stsPolicy\": {\n" +
                "    \"mode\": \"enforce\",\n" +
                "    \"max_age\": \"604800\",\n" +
                "    \"valid\": \"true\",\n" +
                "    \"mx\": \"*.mimecast.com\",\n" +
                "    \"version\": \"STSv1\"\n" +
                "  },\n" +
                "  \"certificateChain\": [],\n" +
                "  \"tlsRecord\": {\n" +
                "    \"valid\": \"true\",\n" +
                "    \"version\": \"TLSRPTv1\",\n" +
                "    \"rua\": \"mailto:tlsrpt@mimecast.com\"\n" +
                "  },\n" +
                "  \"mxList\": [\n" +
                "    {\n" +
                "      \"entry\": \"service-alpha-inbound-a.mimecast.com\",\n" +
                "      \"priority\": \"1\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"entry\": \"service-alpha-inbound-b.mimecast.com\",\n" +
                "      \"priority\": \"1\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"warnings\": [\n" +
                "    \"Max age less than config min: 86400 \\u003c 604800\"\n" +
                "  ],\n" +
                "  \"stsRecord\": {\n" +
                "    \"valid\": \"true\",\n" +
                "    \"location\": \"_mta-sts.mimecast.com\",\n" +
                "    \"id\": \"19840507T234501\",\n" +
                "    \"version\": \"STSv1\"\n" +
                "  },\n" +
                "  \"errors\": []\n" +
                "}";
        assertEquals(expected, logs.get(5));
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
}
