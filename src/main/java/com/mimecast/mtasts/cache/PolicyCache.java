package com.mimecast.mtasts.cache;

import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.assets.StsRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;

/**
 * Policy cache.
 * <p>Abstract for policy cache implementation.
 * <p>Caching policies is highly recommended to save resources on all sides.
 * <p>High load domains may implement rate limiting to protect their systems from abuse.
 *
 * @see StsPolicy
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public abstract class PolicyCache {
    private static final Logger log = LogManager.getLogger(PolicyCache.class);

    /**
     * Puts policy in cache.
     * <p>Invalid and expired policies will not be cached.
     *
     * @param policy StsPolicy instance.
     */
    public void put(StsPolicy policy) {
        if (policy.isValid() && !policy.isExpired()) {
            add(policy);
        }
    }

    /**
     * Gets policy from cache by StsRecord.
     * <p>Requires a fresh StsRecord instance for update and expiry check.
     * <p>Validates before returning found policies.
     * <p>Checks policy record ID matched provided record ID.
     * <p>Checks policy has not expired.
     * <p>Removes from cache if ID not matched or expired.
     *
     * @param record StsRecord instance.
     * @return Optional of StsPolicy instance.
     */
    public Optional<StsPolicy> getByRecord(StsRecord record) {
        if (record != null) {
            StsPolicy policy = lookup(record.getDomain());

            if (policy != null) {

                // Validate record and cache policy ID match.
                if (policy.getRecord().getId().equals(record.getId())) {
                    policy.setCached(true);
                    return Optional.of(policy);
                }
                else {
                    log.info("Record and policy ID mismatch, removing policy from cache");
                    remove(record.getDomain());
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Gets policy from cache by Domain.
     * <p>Failsafe cache lookup if no DNS record found.
     *
     * @param domain Domain string.
     * @return Optional of StsPolicy instance.
     */
    public Optional<StsPolicy> getByDomain(String domain) {
        if (domain != null) {
            StsPolicy policy = lookup(domain);

            if (policy != null) {
                policy.setCached(true);
                return Optional.of(policy);
            }
        }

        return Optional.empty();
    }

    /**
     * Adds policy to cache.
     * <p>Abstract for policy caching.
     *
     * @param policy StsPolicy instance.
     */
    protected abstract void add(StsPolicy policy);

    /**
     * Lookup policy in cache.
     * <p>Abstract for policy lookup in cache.
     *
     * @param domain Domain string.
     * @return StsPolicy instance.
     */
    protected abstract StsPolicy lookup(String domain);

    /**
     * Remove policy from cache.
     * <p>Abstract for policy removal from cache.
     *
     * @param domain Domain string.
     */
    protected abstract void remove(String domain);

    /**
     * Gets cache size.
     * <p>Abstract for cache size fetching.
     * <p>For testing.
     *
     * @return Integer.
     */
    abstract int size();
}
