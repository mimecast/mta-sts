package com.mimecast.mtasts.assets;

/**
 * DNS Record interface.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public interface DnsRecord {

    /**
     * Gets name.
     *
     * @return Name string.
     */
    String getName();

    /**
     * Gets priority.
     *
     * @return Priority integer.
     */
    int getPriority();
}
