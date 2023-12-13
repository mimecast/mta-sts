package com.mimecast.mtasts.assets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StsReportTest {

    @Test
    void valid() {
        // mailto:
        StsReport report = new StsReport("v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com");

        assertTrue(report.isValid());

        assertEquals("v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com", report.getRecord());

        assertEquals("TLSRPTv1", report.getVersion());
        assertEquals(1, report.getRua().size());
        assertEquals("mailto:tlsrpt@mimecast.com", report.getRua().get(0));

        // HTTPS
        report = new StsReport("v=TLSRPTv1; rua=https://tlsrpt.mimecast.com/v1");

        assertTrue(report.isValid());

        assertEquals("v=TLSRPTv1; rua=https://tlsrpt.mimecast.com/v1", report.getRecord());

        assertEquals("TLSRPTv1", report.getVersion());
        assertEquals(1, report.getRua().size());
        assertEquals("https://tlsrpt.mimecast.com/v1", report.getRua().get(0));

        // HTTPS Equals
        report = new StsReport("v=TLSRPTv1; rua=https://tlsrpt.mimecast.com/v1.app?val=1");

        assertTrue(report.isValid());

        assertEquals("v=TLSRPTv1; rua=https://tlsrpt.mimecast.com/v1.app?val=1", report.getRecord());

        assertEquals("TLSRPTv1", report.getVersion());
        assertEquals(1, report.getRua().size());
        assertEquals("https://tlsrpt.mimecast.com/v1.app?val=1", report.getRua().get(0));

        // BOTH
        report = new StsReport("v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com,https://tlsrpt.mimecast.com/v1");

        assertTrue(report.isValid());

        assertEquals("v=TLSRPTv1; rua=mailto:tlsrpt@mimecast.com,https://tlsrpt.mimecast.com/v1", report.getRecord());

        assertEquals("TLSRPTv1", report.getVersion());
        assertEquals(2, report.getRua().size());
        assertEquals("mailto:tlsrpt@mimecast.com", report.getRua().get(0));
        assertEquals("https://tlsrpt.mimecast.com/v1", report.getRua().get(1));
    }

    @Test
    void noRua() {
        StsReport report = new StsReport("v=TLSRPTv1;");
        assertFalse(report.isValid());
    }

    @Test
    void invalidBlank() {
        StsReport report = new StsReport("");
        assertFalse(report.isValid());
    }

    @Test
    void invalidMissingVersion() {
        StsReport report = new StsReport("rua=mailto:tlsrpt@mimecast.com");
        assertFalse(report.isValid());
    }

    @Test
    void invalidMissingId() {
        StsReport report = new StsReport("v=TLSRPTv;");
        assertFalse(report.isValid());
    }

    @Test
    void invalidToken() {
        StsReport report = new StsReport("v-TLSRPTv1 rua=mailto:tlsrpt@mimecast.com");
        assertFalse(report.isValid());
    }

    @Test
    void invalidRua() {
        // Blank
        StsReport report = new StsReport("v=TLSRPTv1; rua=");
        assertFalse(report.isValid());

        report = new StsReport("v=TLSRPTv1; rua=mailto:");
        assertFalse(report.isValid());

        // mailto:
        report = new StsReport("v=TLSRPTv1; rua=mailto:tlsrpt.mimecast.com");
        assertFalse(report.isValid());

        // HTTPS
        report = new StsReport("v=TLSRPTv1; rua=https://tlsrpt-mimecast-com/v1");
        assertFalse(report.isValid());
    }

    @Test
    void invalidVersion() {
        StsReport report = new StsReport("v=TLSRPTv2; rua=mailto:tlsrpt@mimecast.com");
        assertFalse(report.isValid());
    }
}