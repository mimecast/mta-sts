package com.mimecast.mtasts.assets;

import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * Strict Transport Security DNS TXT Abstract.
 * <p>Parser for DNS TXT record contents.
 *
 * @see StsRecord
 * @see StsReport
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public abstract class StsDnsTxt {

    /**
     * Record string.
     */
    private final String record;

    /**
     * Tokens list.
     */
    final Map<String, String> tokens = new HashMap<>();

    /**
     * Constructs a new StsDnsTxt instance.
     * <p>The parser will not except on parsing so it should always be validated via the provided isValid() method.
     *
     * @param record Record string.
     */
    StsDnsTxt(String record) {
        this.record = record.replaceAll("^\"|\"$", "");

        // Relaxed tokenize by semicolon and space.
        StringTokenizer tokenizer = new StringTokenizer(this.record, ";| ");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            if (token.contains("=")) {
                String[] splits = token.split("=");
                if (splits.length == 2) {
                    tokens.put(splits[0].trim(), splits[1].trim());
                }
            }
        }
    }

    /**
     * Gets record.
     *
     * @return Record string.
     */
    public String getRecord() {
        return record;
    }

    /**
     * Is valid.
     *
     * @return Boolean.
     */
    public abstract boolean isValid();

    /**
     * Gets version.
     *
     * @return Version string.
     */
    public String getVersion() {
        return tokens.get("v");
    }

    /**
     * To string.
     *
     * @return Record string.
     */
    @Override
    public String toString() {
        return record;
    }
}
