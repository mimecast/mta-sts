package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.DnsRecord;
import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.assets.StsReport;

import java.util.List;
import java.util.Optional;

/**
 * Dns Record Client.
 * <p>DNS TXT record lookup client interface specific for MTA-STS.
 *
 * @see XBillDnsRecordClient
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
public interface DnsRecordClient {

    /**
     * Gets DNS TXT MTA-STS record.
     *
     * @param domain Domain string.
     * @return Optional of StsRecord instance.
     */
    Optional<StsRecord> getStsRecord(String domain);

    /**
     * Gets DNS TXT TLSRPT record.
     *
     * @param domain Domain string.
     * @return Optional of StsReport instance.
     */
    Optional<StsReport> getRptRecord(String domain);

    /**
     * Gets DNS MX records.
     *
     * @param domain Domain string.
     * @return Optional of List of MXRecord instances.
     */
    Optional<List<DnsRecord>> getMxRecords(String domain);
}
