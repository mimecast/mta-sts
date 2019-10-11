package com.mimecast.mtasts.cache;

import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.assets.StsRecord;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings({"OptionalGetWithoutIsPresent","squid:S2925"})
class MemoryPolicyCacheTest {

    @Test
    void valid() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234501;");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        MemoryPolicyCache cache = new MemoryPolicyCache();
        cache.put(policy);

        StsRecord newRecord = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234501;");
        StsPolicy cachePolicy = cache.getByRecord(newRecord).get();

        assertTrue(cachePolicy.isValid());
        assertEquals("STSv1", cachePolicy.getVersion());
        assertEquals("enforce", cachePolicy.getMode().toString());
        assertEquals(604800, cachePolicy.getMaxAge());

        assertEquals(1, cachePolicy.getMxMasks().size());
        assertEquals("service-alpha-inbound-*.mimecast.com", cachePolicy.getMxMasks().get(0));

        assertTrue(cachePolicy.getRecord().isValid());
        assertEquals("STSv1", cachePolicy.getRecord().getVersion());
        assertEquals("19840507T234501", cachePolicy.getRecord().getId());
    }

    @Test
    void invalid() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234501;");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 86400\r\n");

        MemoryPolicyCache cache = new MemoryPolicyCache();
        cache.put(policy);

        StsRecord newRecord = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234502;");
        Optional<StsPolicy> cachePolicy = cache.getByRecord(newRecord);

        assertFalse(cachePolicy.isPresent());
    }

    @Test
    void getNull() {
        MemoryPolicyCache cache = new MemoryPolicyCache();

        StsRecord newRecord = new StsRecord("mimecast.org", "v=STSv1; id=19840507T234502;");
        Optional<StsPolicy> cachePolicy = cache.getByRecord(newRecord);

        assertFalse(cachePolicy.isPresent());

        Optional<StsPolicy> nullPolicy = cache.getByRecord(null);
        assertFalse(nullPolicy.isPresent());

        nullPolicy = cache.getByDomain(null);
        assertFalse(nullPolicy.isPresent());
    }

    @Test
    void many() {
        MemoryPolicyCache cache = new MemoryPolicyCache();

        StsRecord record;
        StsPolicy policy;

        for (int i = 0; i < 105; i++) {
            record = new StsRecord("mimecast" + i + ".com", "v=STSv1; id=" + i + ";");
            policy = new StsPolicy(record, "version: STSv1\r\n" +
                    "mode: enforce\r\n" +
                    "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                    "max_age: 86400\r\n");
            cache.put(policy);
        }

        assertEquals(100, cache.size());
    }

    @Test
    void expired() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234501;");
        StsPolicy policy = new StsPolicy(record, "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: service-alpha-inbound-*.mimecast.com\r\n" +
                "max_age: 0\r\n");

        MemoryPolicyCache cache = new MemoryPolicyCache();
        cache.put(policy);

        assertFalse(policy.isExpired());
        assertEquals(604800, policy.getMaxAge());

        StsRecord newRecord = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234502;");
        assertFalse(cache.getByRecord(newRecord).isPresent());
    }
}
