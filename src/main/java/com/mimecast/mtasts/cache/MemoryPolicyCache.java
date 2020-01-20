package com.mimecast.mtasts.cache;

import com.mimecast.mtasts.assets.StsPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Memory policy cache.
 * <p>Stores StsPolicy instances in a deque map.
 * <p>For perfomance reasons this is limited to 100 entries.
 * <p>In production environments a cloud cache implementation should be used instead.
 *
 * @see StsPolicy
 * @see PolicyCache
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class MemoryPolicyCache extends PolicyCache {

    /**
     * Deque cache.
     */
    private static final LinkedHashMap<String, StsPolicy> map = new LinkedHashMap<String, StsPolicy>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, StsPolicy> eldest) {
            return this.size() > 100; // Limit.
        }
    };

    /**
     * Adds policy to cache.
     * <p>Implementation of policy caching.
     *
     * @param policy StsPolicy instance.
     */
    @Override
    protected void add(StsPolicy policy) {
        map.put(policy.getRecord().getDomain(), policy);
    }

    /**
     * Lookup policy in cache.
     * <p>Implementation of policy lookup in cache.
     *
     * @return StsPolicy instance.
     */
    @Override
    protected StsPolicy lookup(String domain) {
        return map.get(domain);
    }

    /**
     * Remove policy from cache.
     * <p>Implementation of policy removal from cache.
     *
     * @param domain Domain string.
     */
    @Override
    protected void remove(String domain) {
        map.remove(domain);
    }

    /**
     * Gets cache size.
     * <p>Implementation of cache size getter.
     * <p>For testing.
     *
     * @return Integer.
     */
    @Override
    int size() {
        return map.size();
    }
}
