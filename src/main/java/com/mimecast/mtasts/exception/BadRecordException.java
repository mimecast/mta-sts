package com.mimecast.mtasts.exception;

/**
 * Record Exception.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class BadRecordException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public BadRecordException(String message) {
        super(message);
    }
}
