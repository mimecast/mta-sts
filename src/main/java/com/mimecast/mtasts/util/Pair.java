package com.mimecast.mtasts.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Pair key/value store.
 * <p>Takes a single string input and splits by <i>=</i> (equals) character.
 * <p>Provides validation by checking both key and value and not empty.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class Pair {
    private static final Logger log = LogManager.getLogger(Pair.class);

    /**
     * Key string.
     */
    private String key = "";

    /**
     * Value string.
     */
    private String value = "";

    /**
     * Constructs a new Pair instance with given string.
     *
     * @param key: value
     */
    public Pair(String data) {
        String[] splits = data.trim().split(":");
        if (splits.length == 2) {
            this.key = splits[0].trim();
            this.value = splits[1].trim();
        }
    }

    /**
     * Gets key.
     *
     * @return String.
     */
    public String getKey() {
        return key;
    }

    /**
     * Gets value.
     *
     * @return String.
     */
    public String getValue() {
        return value;
    }

    /**
     * Is valid.
     *
     * @return Boolean.
     */
    public boolean isValid() {
        if (key.equals("mx") && value.contains("*") && !value.startsWith("*")) {
            log.error("Policy MX wildcard is not left-most label within the identifier");
            return false;
        }

        return !key.isEmpty() && !value.isEmpty();
    }

    /**
     * To String.
     *
     * @return String.
     */
    @Override
    public String toString() {
        return !key.isEmpty() ? key + ": " + value : "";
    }
}
