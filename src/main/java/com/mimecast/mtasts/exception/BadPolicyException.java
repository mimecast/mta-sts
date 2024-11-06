package com.mimecast.mtasts.exception;

/**
 * Policy Exception.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public class BadPolicyException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public BadPolicyException(String message) {
        super(message);
    }
}
