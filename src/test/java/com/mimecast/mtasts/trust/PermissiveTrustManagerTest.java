package com.mimecast.mtasts.trust;

import org.junit.jupiter.api.Test;

import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

class PermissiveTrustManagerTest {

    @Test
    void use() throws CertificateException {
        PermissiveTrustManager tm = new PermissiveTrustManager();
        tm.checkClientTrusted(null, null);
        tm.checkServerTrusted(null, null);
        assertTrue(tm.isClientTrusted(null));
        assertTrue(tm.isHostTrusted(null));
    }
}