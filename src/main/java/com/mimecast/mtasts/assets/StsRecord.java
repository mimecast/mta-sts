package com.mimecast.mtasts.assets;

/**
 * Strict Transport Security Record.
 * <p>Parser for MTA-STS DNS TXT record contents.
 * <p>Once constructed all data can be retrieved.
 * <p>Primary scope is for ID fetching for record update check.
 *
 * @link https://tools.ietf.org/html/rfc8461#section-3.1 RFC8461#section-3.1
 *
 * @see StsPolicy
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public final class StsRecord extends StsDnsTxt {

    /**
     * Domain string.
     */
    private final String domain;

    /**
     * Constructs a new StsRecord instance.
     * <p>Domain is required for refference and cache storage and lookup.
     * <p>The parser will not except on parsing so it should always be validated via the provided isValid() method.
     *
     * @param domain Domain string.
     * @param record Record string.
     */
    public StsRecord(String domain, String record) {
        super(record);
        this.domain = domain;
    }

    /**
     * Gets domain.
     *
     * @return Domain string.
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Is valid.
     * <p>Checks both v (version) and ID are declared.
     * <p>Only version 1 accepted but matched case insensitive to be more relaxed.
     *
     * @return Boolean.
     */
    public boolean isValid() {
        return tokens.containsKey("v") && tokens.get("v").equalsIgnoreCase("STSv1") && tokens.containsKey("id") && tokens.get("id").length() > 0;
    }

    /**
     * Gets ID.
     *
     * @return ID string.
     */
    public String getId() {
        return tokens.get("id");
    }
}
