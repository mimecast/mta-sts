package com.mimecast.mtasts;

import com.mimecast.mtasts.assets.DnsRecord;
import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.assets.StsReport;
import com.mimecast.mtasts.cache.PolicyCache;
import com.mimecast.mtasts.client.*;
import com.mimecast.mtasts.config.Config;
import com.mimecast.mtasts.exception.BadPolicyException;
import com.mimecast.mtasts.exception.BadRecordException;
import com.mimecast.mtasts.exception.NoRecordException;
import org.apache.commons.validator.ValidatorException;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Strict Transport Security.
 * <p>Implementation of MTA-STS RFC8461.
 *
 * @link https://tools.ietf.org/html/rfc8461 RFC8461
 *
 * @see XBillDnsRecordClient
 * @see OkHttpsPolicyClient
 * @see PolicyCache
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
@SuppressWarnings("WeakerAccess")
public class StrictTransportSecurity {
    private static final Logger log = LogManager.getLogger(StrictTransportSecurity.class);

    /**
     * DnsRecordClient instance.
     */
    private final DnsRecordClient dnsRecordClient;

    /**
     * HttpsPolicyClient instance.
     */
    private final HttpsPolicyClient httpsPolicyClient;

    /**
     * PolicyCache instance.
     */
    private final PolicyCache cache;

    /**
     * Constructs a new StrictTransportSecurity instance.
     * <p>Cache can be null.
     * <p>For testing and CLI.
     *
     * @param dnsRecordClient   DnsRecordClient instance.
     * @param httpsPolicyClient HttpsPolicyClient instance.
     * @throws InstantiationException Null argument(s) provided.
     */

    StrictTransportSecurity(DnsRecordClient dnsRecordClient, HttpsPolicyClient httpsPolicyClient) throws InstantiationException {
        this(dnsRecordClient, httpsPolicyClient, null);
    }

    /**
     * Constructs a new StrictTransportSecurity instance.
     * <p>Arguments cannot be null.
     *
     * @param dnsRecordClient   DnsRecordClient instance.
     * @param httpsPolicyClient HttpsPolicyClient instance.
     * @param cache             PolicyCache instance.
     * @throws InstantiationException Null argument(s) provided.
     */
    public StrictTransportSecurity(DnsRecordClient dnsRecordClient, HttpsPolicyClient httpsPolicyClient, PolicyCache cache) throws InstantiationException {
        if (dnsRecordClient == null || httpsPolicyClient == null) {
            throw new InstantiationException("DnsRecordClient and/or HttpsPolicyClient cannot be null");
        }
        this.dnsRecordClient = dnsRecordClient;
        this.httpsPolicyClient = httpsPolicyClient;
        this.cache = cache;
    }

    /**
     * Gets policy with given domain string.
     * <p>Fetches DNS record every time.
     * <p>Checks record is valid.
     * <p>Tryes to get policy from cache.
     * <p>If policy is not in cache will fetch and put it in cache.
     *
     * @param domain Domain string.
     * @return Optional of StsPolicy instance.
     * @throws ValidatorException Domain provided is invalid.
     * @throws BadPolicyException HTTPS policy is invalid or not found.
     * @throws BadRecordException DNS record is invalid or not found.
     */
    public Optional<StsPolicy> getPolicy(String domain) throws ValidatorException, NoRecordException, BadRecordException, BadPolicyException {
        return getPolicy(domain, null);
    }

    /**
     * Gets policy with given domain string and config instance.
     * <p>Fetches DNS record every time.
     * <p>Checks record is valid.
     * <p>Tryes to get policy from cache.
     * <p>If policy is not in cache will fetch and put it in cache.
     * <p>Config instance can be used to modify validation checks.
     *
     * @param domain Domain string.
     * @param config Config instance.
     * @return Optional of StsPolicy instance.
     * @throws ValidatorException Domain provided is invalid.
     * @throws BadPolicyException HTTPS policy is invalid or not found.
     * @throws BadRecordException DNS record is invalid or not found.
     */
    public Optional<StsPolicy> getPolicy(String domain, Config config) throws ValidatorException, NoRecordException, BadRecordException, BadPolicyException {
        StsPolicy policy;

        // Validate domain.
        if (DomainValidator.getInstance(false).isValid(domain)) {

            // Get DNS TXT record.
            Optional<StsRecord> optional = dnsRecordClient.getStsRecord(domain);
            if (optional.isPresent() && optional.get().isValid()) {
                log.info("Record found and valid");

                // Search policy in cache or fetch from HTTPS.
                policy = getPolicy(optional.get(), config);

                // Validate policy.
                if (!policy.isValid() || policy.isExpired()) {
                    throw new BadPolicyException("Policy invalid for: " + domain);
                }
            }
            else if (!optional.isPresent()) {
                log.warn("Record not found, searching cache for policy");

                // Search policy in cache.
                policy = searchPolicyCache(domain);

                if (policy == null) {
                    throw new NoRecordException("Record not found for: " + domain);
                }
            }
            else {
                throw new BadRecordException("Record invalid for: " + domain);
            }
        }
        else {
            throw new ValidatorException("Domain invalid: " + domain);
        }

        return Optional.of(fetchRptRecord(policy));
    }

    /**
     * Gets policy from cache if any.
     *
     * @param record StsRecord instance.
     * @param config Config instance.
     * @return StsPolicy instance.
     */
    private StsPolicy getPolicy(StsRecord record, Config config) {
        // Search policy in cache first.
        StsPolicy policy = searchPolicyCache(record);

        // Fetch policy if not in cache or expired.
        if (policy == null || policy.isExpired()) {
            return fetchPolicyHttps(record, config);
        }

        return policy;
    }

    /**
     * Gets policy from cache by StsRecord.
     *
     * @param record StsRecord instance.
     * @return StsPolicy instance.
     */
    private StsPolicy searchPolicyCache(StsRecord record) {
        StsPolicy policy = null;

        if (cache != null) {
            Optional<StsPolicy> optional = cache.getByRecord(record);
            if (optional.isPresent()) {
                policy = optional.get();
            }
        }

        return policy;
    }

    /**
     * Gets policy from cache by domain.
     *
     * @param domain Domain string.
     * @return StsPolicy instance.
     */
    private StsPolicy searchPolicyCache(String domain) {
        StsPolicy policy = null;

        if (cache != null) {
            Optional<StsPolicy> optional = cache.getByDomain(domain);
            if (optional.isPresent()) {
                policy = optional.get();
            }
        }

        return policy;
    }

    /**
     * Gets policy from well known HTTPS address.
     *
     * @param record StsRecord instance.
     * @param config Config instance.
     * @return StsPolicy instance.
     */
    private StsPolicy fetchPolicyHttps(StsRecord record, Config config) {
        HttpsResponse response = httpsPolicyClient.getPolicy(record);

        StsPolicy policy = new StsPolicy(record, response);

        if (config != null) {
            policy.setConfig(config);
        }

        policy.make();

        if (policy.isValid() && cache != null) {
            cache.put(policy);
        }

        return policy;
    }

    /**
     * Gets TLSRPT record.
     *
     * @param policy StsPolicy instance.
     * @return StsPolicy instance.
     */
    private StsPolicy fetchRptRecord(StsPolicy policy) {
        Optional<StsReport> optional = dnsRecordClient.getRptRecord(policy.getRecord().getDomain());
        if (optional.isPresent() && optional.get().isValid()) {
            policy.setReport(optional.get());
        }

        return policy;
    }

    /**
     * Gets MX records.
     * <p>On demand lookup.
     *
     * @param domain Domain name.
     * @return List of MXRecord.
     */
    public List<DnsRecord> getMxRecords(String domain) {
        Optional<List<DnsRecord>> optional = dnsRecordClient.getMxRecords(domain);
        List<DnsRecord> mxRecords = optional.orElseGet(ArrayList::new);

        Comparator<DnsRecord> compareByName = Comparator.comparing(DnsRecord::getName);
        mxRecords.sort(compareByName);

        Comparator<DnsRecord> compareByPriority = Comparator.comparingInt(DnsRecord::getPriority);
        mxRecords.sort(compareByPriority);

        return mxRecords;
    }
}
