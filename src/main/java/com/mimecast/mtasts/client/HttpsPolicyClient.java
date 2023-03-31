package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.exception.PolicyFetchErrorException;
import com.mimecast.mtasts.exception.PolicyWebPKIInvalidException;

/**
 * Https Policy Client.
 * <p>HTTPS client interface specific for MTA-STS.
 *
 * @link <a href="https://tools.ietf.org/html/rfc8461#section-3.3">RFC8461#section-3.3</a>
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public interface HttpsPolicyClient {

    /**
     * Gets policy.
     * <p>Requires a fresh StsRecord instance to get the domain from and construct the StsPolicy instance.
     *
     * @param stsRecord StsRecord instance.
     * @param maxPolicyBodySize The maximum size of the policy body.
     * @return OkHttpsResponse instance.
     * @throws PolicyWebPKIInvalidException Policy web PKI invalid exception.
     * @throws PolicyFetchErrorException Policy fetch error exception.
     */
    OkHttpsResponse getPolicy(StsRecord stsRecord, int maxPolicyBodySize) throws PolicyWebPKIInvalidException, PolicyFetchErrorException;
}
