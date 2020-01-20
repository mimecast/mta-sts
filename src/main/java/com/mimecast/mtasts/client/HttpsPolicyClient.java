package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;

/**
 * Https Policy Client.
 * <p>HTTPS client interface specific for MTA-STS.
 *
 * @link https://tools.ietf.org/html/rfc8461#section-3.3 RFC8461#section-3.3
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public interface HttpsPolicyClient {

    /**
     * Gets policy.
     * <p>Requires a fresh StsRecord instance to get the domain from and construct the StsPolicy instance.
     *
     * @param record StsRecord instance.
     * @return OkHttpsResponse instance.
     */
    OkHttpsResponse getPolicy(StsRecord record);
}
