package com.mimecast.mtasts.exception;

/**
 * Policy Exception.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class BadPolicyException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public BadPolicyException(String message) {
        super(message);
    }
}
