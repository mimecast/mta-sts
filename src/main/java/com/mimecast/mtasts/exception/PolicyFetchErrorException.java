package com.mimecast.mtasts.exception;

/**
 * Policy fetch error exception.
 *
 * @author "Sumon Selim" <sselim@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public class PolicyFetchErrorException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     */
    public PolicyFetchErrorException(String message) {
        super(message);
    }
}
