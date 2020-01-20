package com.mimecast.mtasts.assets;

import com.mimecast.mtasts.client.HttpsResponseMock;
import com.mimecast.mtasts.config.Config;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidParameterException;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class StsPolicyTest {

    @Test
    void valid() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());

        assertEquals("STSv1", policy.getVersion());
        assertEquals("enforce", policy.getMode().toString());
        assertEquals(604800, policy.getMaxAge());
        assertEquals(2, policy.getMxMasks().size());
        assertEquals("service-alpha-inbound-a.mimecast.com", policy.getMxMasks().get(0));
        assertEquals("service-alpha-inbound-b.mimecast.com", policy.getMxMasks().get(1));
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void matchMxEnforce() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.matchMx("service-alpha-inbound-a.mimecast.com"));
        assertTrue(policy.matchMx("service-alpha-inbound-b.mimecast.com"));
        assertFalse(policy.matchMx("mimecast.net"));
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void matchMxTesting() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.matchMx("service-alpha-inbound-a.mimecast.com"));
        assertTrue(policy.matchMx("service-alpha-inbound-b.mimecast.com"));
        assertTrue(policy.matchMx("mimecast.net"));
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void matchMxFalse() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidKey() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: pretend\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n" +
                "min_age: 300\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidMalformed() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode none\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidValue() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age:\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertEquals("Max age less than config min: 0 < 604800", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void invalidMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: pretend\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void noneMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: none\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void testingMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidModeNone() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidMxNone() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "max_age: 604800\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidMaxAge() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: *.mimecast.com\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertEquals(86400, policy.getMaxAge());
        assertFalse(policy.isCached());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertEquals("Max age less than config soft min: 0 < 86400", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void overMax() {
        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 31557601";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy EOL not found", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertEquals("Max age more than config max: 31557601 > 31557600", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void underMin() {
        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 604799";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy EOL not found", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertEquals("Max age less than config min: 604799 < 604800", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void underSoftMin() {
        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 31557601";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy EOL not found", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertEquals("Max age more than config max: 31557601 > 31557600", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void expired() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 1\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isExpired());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertEquals("Max age less than config min: 1 < 604800", policy.getValidator().getWarnings().get(0));
        assertEquals(1, policy.getValidator().getWarnings().size());
    }

    @Test
    void configRelaxed() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r" +
                "mode: enforce\r" +
                "mx: *.mimecast.com\r" +
                "max_age: 1\r";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        Config config = new Config()
                .setConnectTimeout(10)
                .setWriteTimeout(10)
                .setReadTimeout(10)
                .setRequireTextPlain(false)
                .setRequireCRLF(false)
                .setPolicyMaxBodySize(64)
                .setPolicyMaxAge(60)
                .setPolicyMinAge(30)
                .setPolicySoftMinAge(1);

        StsPolicy policy = new StsPolicy(record, httpsResponse).setConfig(config).make();

        assertTrue(policy.isValid());
        assertFalse(policy.isExpired());
        assertFalse(policy.isCached());
        assertEquals("STSv1", policy.getVersion());
        assertEquals("enforce", policy.getMode().toString());
        assertEquals(1, policy.getMxMasks().size());
        assertEquals(30, policy.getMaxAge());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertTrue(policy.getValidator().getErrors().isEmpty());
        assertEquals("Policy EOL not CRLF", policy.getValidator().getWarnings().get(0));
        assertEquals(2, policy.getValidator().getWarnings().size());
    }

    @Test
    void string() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86399\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        String actual = policy.asString();
        long fetchTime = policy.getFetchTime();

        assertTrue(actual.contains("version: STSv1\r\n"));
        assertTrue(actual.contains("mode: enforce\r\n"));
        assertTrue(actual.contains("mx: *.mimecast.com\r\n"));
        assertTrue(actual.contains("max_age: 604800\r\n"));
        assertTrue(actual.contains("fetch_time: " + fetchTime + "\r\n"));
        assertTrue(actual.contains("domain: mimecast.com\r\n"));
        assertTrue(actual.contains("record_id: 19840507T234501\r\n"));

        policy = new StsPolicy(actual).make();
        actual = policy.asString();

        assertTrue(actual.contains("version: STSv1\r\n"));
        assertTrue(actual.contains("mode: enforce\r\n"));
        assertTrue(actual.contains("mx: *.mimecast.com\r\n"));
        assertTrue(actual.contains("max_age: 604800\r\n"));
        assertTrue(actual.contains("fetch_time: " + fetchTime + "\r\n"));
        assertTrue(actual.contains("domain: mimecast.com\r\n"));
        assertTrue(actual.contains("record_id: 19840507T234501\r\n"));
    }

    @Test
    void invalidLF() {
        String policyBody = "version: STSv1\n" +
                "mode: enforce\n" +
                "mx: service-alpha-inbound-a.mimecast.com\n" +
                "mx: service-alpha-inbound-b.mimecast.com\n" +
                "max_age: 604800\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(policyBody, policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy EOL not CRLF", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void emptyLine() {
        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 604800\r\n\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy does not support empty lines", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void noLastCRLF() {
        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 604800";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, httpsResponse).make();

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(httpsResponse.getBody(), policy.getPolicy());
        assertEquals(httpsResponse.getBody(), policy.toString());
        assertEquals("Policy EOL not found", policy.getValidator().getErrors().get(0));
        assertEquals(1, policy.getValidator().getErrors().size());
        assertTrue(policy.getValidator().getWarnings().isEmpty());
    }

    @Test
    void invalidString() {
        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n" +
                "fetch_time: 1566215506\r\n" +
                "domain: mimecast\r\n" +
                "record_id: 19840507T234501\r\n").make());

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n" +
                "fetch_time: 0\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: 19840507T234501\r\n").make());

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n" +
                "fetch_time: 1566215506\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: \r\n").make());

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n" +
                "fetch_time: abc\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: 19840507T234501\r\n").make());

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n").make());
    }

    @Test
    void stringException() {
        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 604800\r\n").make());
    }
}
