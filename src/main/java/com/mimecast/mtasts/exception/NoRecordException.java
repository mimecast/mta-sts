package com.mimecast.mtasts.exception;

/**
 * DNS Exception.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public class NoRecordException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public NoRecordException(String message) {
        super(message);
    }
}
