package com.mimecast.mtasts.util;

/**
 * Pair key/value store.
 * <p>Takes a single string input and splits by <i>=</i> (equals) character.
 * <p>Provides validation by checking both key and value and not empty.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class Pair {

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
     * @param data Key=value string.
     */
    public Pair(String data) {
        String[] splits = data.split(":");
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
        return !key.isEmpty() &&  !value.isEmpty();
    }

    /**
     * To String.
     *
     * @return String.
     */
    @Override
    public String toString() {
        return key + "=" + value;
    }
}
