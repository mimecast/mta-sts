package com.mimecast.mtasts.config;

/**
 * Config.
 * <p>Gives fine control over validations.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class Config {

    /**
     * HTTPS connection timeout (in seconds).
     */
    private int connectTimeout = 60;

    /**
     * Gets HTTPS connection timeout.
     *
     * @return Integer.
     */
    public int getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * Sets connection timeout.
     *
     * @param connectTimeout Integer.
     * @return Self.
     */
    public Config setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
        return this;
    }

    /**
     * HTTPS write timeout (in seconds).
     */
    private int writeTimeout = 60;

    /**
     * Gets HTTPS write timeout.
     *
     * @return Integer.
     */
    public int getWriteTimeout() {
        return writeTimeout;
    }

    /**
     * Sets write timeout.
     *
     * @param writeTimeout Integer.
     * @return Self.
     */
    public Config setWriteTimeout(int writeTimeout) {
        this.writeTimeout = writeTimeout;
        return this;
    }

    /**
     * HTTPS read timeout (in seconds).
     */
    private int readTimeout = 60;

    /**
     * Gets HTTPS read timeout.
     *
     * @return Integer.
     */
    public int getReadTimeout() {
        return readTimeout;
    }

    /**
     * Sets read timeout.
     *
     * @param readTimeout Integer.
     * @return Self.
     */
    public Config setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
        return this;
    }

    /**
     * Require HTTPS response Content-Type as text/plain.
     */
    protected boolean requireTextPlain = true;

    /**
     * Is required text/plain.
     *
     * @return Boolean.
     */
    public boolean isRequireTextPlain() {
        return requireTextPlain;
    }

    /**
     * Sets required text/plain.
     *
     * @param requireTextPlain Boolean.
     * @return Self.
     */
    public Config setRequireTextPlain(boolean requireTextPlain) {
        this.requireTextPlain = requireTextPlain;
        return this;
    }

    /**
     * Require policy line endings as CRLF.
     */
    protected boolean requireCRLF = true;

    /**
     * Is required policy line endings.
     *
     * @return Boolean.
     */
    public boolean isRequireCRLF() {
        return requireCRLF;
    }

    /**
     * Sets required policy line endings.
     *
     * @param requireCRLF Boolean.
     * @return Self.
     */
    public Config setRequireCRLF(boolean requireCRLF) {
        this.requireCRLF = requireCRLF;
        return this;
    }

    /**
     * Policy max body size (64k).
     */
    private int policyMaxBodySize = 64000;

    /**
     * Gets policy max body size.
     *
     * @return Integer.
     */
    public int getPolicyMaxBodySize() {
        return policyMaxBodySize;
    }

    /**
     * Sets policy max body size.
     *
     * @param policyMaxBodySize Integer.
     * @return Self.
     */
    public Config setPolicyMaxBodySize(int policyMaxBodySize) {
        this.policyMaxBodySize = policyMaxBodySize;
        return this;
    }

    /**
     * Policy max age.
     * <p>365.25 days / ~ 1 year.
     */
    private int policyMaxAge = 31557600;

    /**
     * Gets policy max age.
     *
     * @return Integer.
     */
    public int getPolicyMaxAge() {
        return policyMaxAge;
    }

    /**
     * Sets policy max age.
     *
     * @param policyMaxAge Integer.
     * @return Self.
     */
    public Config setPolicyMaxAge(int policyMaxAge) {
        this.policyMaxAge = policyMaxAge;
        return this;
    }

    /**
     * Policy min age.
     * <p>7 days / 1 week.
     */
    private int policyMinAge = 604800;

    /**
     * Gets policy min age.
     *
     * @return Integer.
     */
    public int getPolicyMinAge() {
        return policyMinAge;
    }

    /**
     * Sets policy min age.
     *
     * @param policyMinAge Integer.
     * @return Self.
     */
    public Config setPolicyMinAge(int policyMinAge) {
        this.policyMinAge = policyMinAge;
        return this;
    }

    /**
     * Policy soft min age.
     * <p>1 day.
     */
    private int policySoftMinAge = 86400;

    /**
     * Gets max age min soft.
     *
     * @return Integer.
     */
    public int getPolicySoftMinAge() {
        return policySoftMinAge;
    }

    /**
     * Sets max age min soft.
     *
     * @param policySoftMinAge Integer.
     * @return Self.
     */
    public Config setPolicySoftMinAge(int policySoftMinAge) {
        this.policySoftMinAge = policySoftMinAge;
        return this;
    }
}
