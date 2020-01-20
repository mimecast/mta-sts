package com.mimecast.mtasts.util;

import java.net.HttpURLConnection;

/**
 * Local HTTPS Response.
 * <p>Holds response payload and meta.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class LocalHttpsResponse {

    /**
     * Content-Type header string.
     * <p>Default: text/plain
     */
    private String contentType = "text/plain";

    /**
     * Gets Content-Type header string.
     *
     * @return String.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Sets Content-Type header string.
     *
     * @param contentType String.
     * @return Self.
     */
    public LocalHttpsResponse setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    /**
     * Response status code.
     * <p>Default: 200 (HTTP_OK)
     *
     * @see HttpURLConnection.HTTP_OK
     */
    private int code = 200;

    /**
     * Gets status code.
     *
     * @return Integer.
     */
    public int getCode() {
        return code;
    }

    /**
     * Sets status code.
     *
     * @param code Integer.
     * @return Self.
     */
    public LocalHttpsResponse setCode(int code) {
        this.code = code;
        return this;
    }

    /**
     * Response string.
     */
    private String responseString;

    /**
     * Gets response string.
     *
     * @return String.
     */
    public String getResponseString() {
        return responseString;
    }

    /**
     * Sets response string.
     *
     * @param responseString String.
     * @return Self.
     */
    public LocalHttpsResponse setResponseString(String responseString) {
        this.responseString = responseString;
        return this;
    }
}
