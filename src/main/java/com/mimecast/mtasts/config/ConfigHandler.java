package com.mimecast.mtasts.config;

/**
 * Config handler abstract.
 * <p>Provides config instance and encapsulation.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public abstract class ConfigHandler {

    /**
     * Config instance.
     */
    protected Config config = new Config();

    /**
     * Gets config.
     *
     * @return Config instance.
     */
    public Config getConfig() {
        return config;
    }

    /**
     * Sets config.
     *
     * @param config Config instance.
     * @return Self.
     */
    public ConfigHandler setConfig(Config config) {
        this.config = config;
        return this;
    }
}
