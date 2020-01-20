package com.mimecast.mtasts.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PairTest {

    @Test
    void valid() {
        Pair pair = new Pair("test: one");
        assertEquals("test", pair.getKey());
        assertEquals("one", pair.getValue());
        assertTrue(pair.isValid());
        assertEquals("test: one", pair.toString());
    }

    @Test
    void invalidValue() {
        Pair pair = new Pair("test: ");
        assertEquals("", pair.getKey());
        assertEquals("", pair.getValue());
        assertFalse(pair.isValid());
        assertEquals("", pair.toString());
    }

    @Test
    void invalidBoth() {
        Pair pair = new Pair("test one");
        assertEquals("", pair.getKey());
        assertEquals("", pair.getValue());
        assertFalse(pair.isValid());
        assertEquals("", pair.toString());
    }
}
