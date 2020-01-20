package com.mimecast.mtasts.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConfigHandlerTest {

    @Test
    void getConfig() {
        ConfigHandler configHandler = new ConfigHandlerMock();
        Config config = configHandler.getConfig();

        assertEquals(60, config.getConnectTimeout());
        assertEquals(60, config.getWriteTimeout());
        assertEquals(60, config.getReadTimeout());
        assertTrue(config.isRequireTextPlain());
        assertTrue(config.isRequireCRLF());
        assertEquals(64000, config.getPolicyMaxBodySize());
        assertEquals(31557600, config.getPolicyMaxAge());
        assertEquals(604800, config.getPolicyMinAge());
        assertEquals(86400, config.getPolicySoftMinAge());
    }

    @Test
    void setConfig() {
        Config config = new Config()
            .setConnectTimeout(10)
            .setWriteTimeout(10)
            .setReadTimeout(10)
            .setRequireTextPlain(false)
            .setRequireCRLF(false)
            .setPolicyMaxBodySize(64)
            .setPolicyMaxAge(86400)
            .setPolicyMinAge(3600)
            .setPolicySoftMinAge(60);

        ConfigHandler configHandler = new ConfigHandlerMock().setConfig(config);
        config = configHandler.getConfig();

        assertEquals(10, config.getConnectTimeout());
        assertEquals(10, config.getWriteTimeout());
        assertEquals(10, config.getReadTimeout());
        assertFalse(config.isRequireTextPlain());
        assertFalse(config.isRequireCRLF());
        assertEquals(64, config.getPolicyMaxBodySize());
        assertEquals(86400, config.getPolicyMaxAge());
        assertEquals(3600, config.getPolicyMinAge());
        assertEquals(60, config.getPolicySoftMinAge());
    }
}