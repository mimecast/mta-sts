package com.mimecast.mtasts.exception;

/**
 * DNS Exception.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class NoRecordException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public NoRecordException(String message) {
        super(message);
    }
}
