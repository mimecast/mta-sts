package com.mimecast.mtasts.assets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StsRecordTest {

    @Test
    void valid() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1; id=19840507T234501;");

        assertTrue(record.isValid());

        assertEquals("mimecast.com", record.getDomain());
        assertEquals("v=STSv1; id=19840507T234501;", record.getRecord());

        assertEquals("STSv1", record.getVersion());
        assertEquals("19840507T234501", record.getId());
    }

    @Test
    void noId() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1;");
        assertFalse(record.isValid());
    }

    @Test
    void invalidBlank() {
        StsRecord record = new StsRecord("mimecast.com", "");
        assertFalse(record.isValid());
    }

    @Test
    void invalidMissingVersion() {
        StsRecord record = new StsRecord("mimecast.com", "id=19840507T234501;");
        assertFalse(record.isValid());
    }

    @Test
    void invalidMissingId() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv;");
        assertFalse(record.isValid());
    }

    @Test
    void invalidToken() {
        StsRecord record = new StsRecord("mimecast.com", "v-STSv1 id=19840507T234501");
        assertFalse(record.isValid());
    }

    @Test
    void invalidId() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv1 id=");
        assertFalse(record.isValid());
    }

    @Test
    void invalidVersion() {
        StsRecord record = new StsRecord("mimecast.com", "v=STSv2; id=19840507T234501;");
        assertFalse(record.isValid());
    }
}
