package com.mimecast.mtasts.assets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidParameterException;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("squid:S2925")
class StsPolicyTest {

    @Test
    void valid() {
        String policyString = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-a.mimecast.com\r\n" +
                "mx: service-alpha-inbound-b.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, policyString);

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(policyString, policy.getPolicy());

        assertEquals("STSv1", policy.getVersion());
        assertEquals("enforce", policy.getMode().toString());
        assertEquals(604800, policy.getMaxAge());
        assertEquals(2, policy.getMxMasks().size());
        assertEquals("service-alpha-inbound-a.mimecast.com", policy.getMxMasks().get(0));
        assertEquals("service-alpha-inbound-b.mimecast.com", policy.getMxMasks().get(1));
    }


    @Test
    void validBareLF() {
        String policyString = "version: STSv1\n" +
                "mode: enforce\n" +
                "mx: service-alpha-inbound-a.mimecast.com\n" +
                "mx: service-alpha-inbound-b.mimecast.com\n" +
                "max_age: 86400\n";

        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, policyString);

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertEquals(policyString, policy.getPolicy());

        assertEquals("STSv1", policy.getVersion());
        assertEquals("enforce", policy.getMode().toString());
        assertEquals(604800, policy.getMaxAge());
        assertEquals(2, policy.getMxMasks().size());
        assertEquals("service-alpha-inbound-a.mimecast.com", policy.getMxMasks().get(0));
        assertEquals("service-alpha-inbound-b.mimecast.com", policy.getMxMasks().get(1));
    }

    @Test
    void matchMxEnforce() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.matchMx("service-alpha-inbound-a.mimecast.com"));
        assertTrue(policy.matchMx("service-alpha-inbound-b.mimecast.com"));
    }

    @Test
    void matchMxTesting() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertTrue(policy.matchMx("service-alpha-inbound-a.mimecast.com"));
        assertTrue(policy.matchMx("service-alpha-inbound-b.mimecast.com"));
    }

    @Test
    void matchMxFalse() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
        assertFalse(policy.matchMx("service-alpha-a.mimecast.com"));
        assertFalse(policy.matchMx("service-alpha-b.mimecast.com"));
    }

    @Test
    void invalidKey() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: pretend\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n" +
                "min_age: 300\r\n");

        assertFalse(policy.isValid());
    }

    @Test
    void invalidMalformed() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode none\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void invalidValue() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age:\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void invalidMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: pretend\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void noneMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: none\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void testingMode() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void invalidModeNone() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void invalidMxNone() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "max_age: 86400\r\n");

        assertFalse(policy.isValid());
        assertFalse(policy.isCached());
    }

    @Test
    void invalidMaxAge() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: testing\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n");

        assertTrue(policy.isValid());
        assertEquals(86400, policy.getMaxAge());
        assertFalse(policy.isCached());
    }

    @Test
    void expired() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 1\r\n");

        assertTrue(policy.isValid());
        assertFalse(policy.isExpired());
    }

    @Test
    void string() {
        StsRecord record = new StsRecord("mimecast.com", "\"v=STSv1; id=19840507T234501;\"");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        String actual = policy.asString();
        long fetchTime = policy.getFetchTime();

        assertTrue(actual.contains("version: STSv1\r\n"));
        assertTrue(actual.contains("mode: enforce\r\n"));
        assertTrue(actual.contains("mx: service-alpha-inbound-*.mimecast.com\r\n"));
        assertTrue(actual.contains("mx: service-alpha-*.mimecast.com\r\n"));
        assertTrue(actual.contains("max_age: 604800\r\n"));
        assertTrue(actual.contains("fetch_time: " + fetchTime + "\r\n"));
        assertTrue(actual.contains("domain: mimecast.com\r\n"));
        assertTrue(actual.contains("record_id: 19840507T234501\r\n"));

        policy = new StsPolicy(actual);
        actual = policy.asString();

        assertTrue(actual.contains("version: STSv1\r\n"));
        assertTrue(actual.contains("mode: enforce\r\n"));
        assertTrue(actual.contains("mx: service-alpha-inbound-*.mimecast.com\r\n"));
        assertTrue(actual.contains("mx: service-alpha-*.mimecast.com\r\n"));
        assertTrue(actual.contains("max_age: 604800\r\n"));
        assertTrue(actual.contains("fetch_time: " + fetchTime + "\r\n"));
        assertTrue(actual.contains("domain: mimecast.com\r\n"));
        assertTrue(actual.contains("record_id: 19840507T234501\r\n"));
    }

    @Test
    void invalidString() {
        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n" +
                "fetch_time: 1566215506\r\n" +
                "domain: mimecast\r\n" +
                "record_id: 19840507T234501\r\n"));

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n" +
                "fetch_time: 0\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: 19840507T234501\r\n"));

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n" +
                "fetch_time: 1566215506\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: \r\n"));

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n" +
                "fetch_time: abc\r\n" +
                "domain: mimecast.com\r\n" +
                "record_id: 19840507T234501\r\n"));

        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "mx: service-alpha-*.mimecast.com\r\n" +
                "max_age: 86400\r\n"));
    }

    @Test
    void stringException() {
        Assertions.assertThrows(InvalidParameterException.class, () -> new StsPolicy("version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n"));
    }
}
