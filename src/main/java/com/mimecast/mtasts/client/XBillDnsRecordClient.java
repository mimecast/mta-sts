package com.mimecast.mtasts.client;

import com.mimecast.mtasts.assets.DnsRecord;
import com.mimecast.mtasts.assets.StsRecord;
import com.mimecast.mtasts.assets.StsReport;
import com.mimecast.mtasts.assets.XBillDnsRecord;
import com.mimecast.mtasts.util.LocalDnsResolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * XBill Dns Record Client.
 * <p>DNS TXT record lookup client implementation specific for MTA-STS.
 * <p>Uses DNS Java library.
 * <p>A custom resolver can be provided via Lookup.setDefaultResolver().
 * <p>One such resolver is provided for testing purposes.
 *
 * @see Lookup
 * @see LocalDnsResolver
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class XBillDnsRecordClient implements DnsRecordClient {
    private static final Logger log = LogManager.getLogger(XBillDnsRecordClient.class);

    /**
     * Gets DNS TXT MTA-STS record.
     * <p>Will query the <i>_mta-sts.</i> subdomain of the domain provided.
     * <p>If multiple MTA-STS records found it will return none.
     *
     * @param domain Domain string.
     * @return Optional of StsRecord instance.
     */
    @Override
    public Optional<StsRecord> getStsRecord(String domain) {
        Record[] recordList = getRecord("_mta-sts." + domain, Type.TXT);
        if (recordList != null) {
            List<StsRecord> records = new ArrayList<>();
            for (Record entry : recordList) {
                StsRecord record = new StsRecord(domain, entry.rdataToString());

                if (record.getVersion() != null && record.getVersion().equalsIgnoreCase("STSv1")) {
                    records.add(record);
                }
            }

            if (records.size() == 1) {
                return Optional.of(records.get(0));
            }
        }

        return Optional.empty();
    }

    /**
     * Gets DNS TXT TLSRPT record.
     * <p>Will query the <i>_smtp._tls.</i> subdomain of the domain provided.
     * <p>If multiple TLSRPT records found it will return none.
     *
     * @param domain Domain string.
     * @return Optional of StsReport instance.
     */
    @Override
    public Optional<StsReport> getRptRecord(String domain) {
        Record[] recordList = getRecord("_smtp._tls." + domain, Type.TXT);
        if (recordList != null) {
            List<StsReport> records = new ArrayList<>();
            for (Record entry : recordList) {
                StsReport record = new StsReport(entry.rdataToString());

                if (record.getVersion() != null && record.getVersion().equalsIgnoreCase("TLSRPTv1")) {
                    records.add(record);
                }
            }

            if (records.size() == 1) {
                return Optional.of(records.get(0));
            }
        }

        return Optional.empty();
    }

    /**
     * Gets DNS MX records.
     * <p>Will query for MX records of the domain provided.
     * <p>Will not fallback to A record if none found.
     *
     * @param domain Domain string.
     * @return Optional of List of MXRecord instances.
     */
    public Optional<List<DnsRecord>> getMxRecords(String domain) {
        Record[] recordList = getRecord(domain, Type.MX);
        if (recordList != null) {
            List<DnsRecord> records = new ArrayList<>();
            for (Record record : recordList) {
                if (record instanceof MXRecord) {
                    records.add(new XBillDnsRecord((MXRecord) record));
                }
            }

            if (!records.isEmpty()) {
                return Optional.of(records);
            }
        }

        return Optional.empty();
    }

    /**
     * Gets DNS TXT record.
     *
     * @param uri  Lookup URI string.
     * @param type Lookup type int.
     * @return Optional of StsRecord instance.
     */
    private Record[] getRecord(String uri, int type) {
        try {
            Lookup lookup = new Lookup(uri, type);
            return lookup.run();
        } catch (TextParseException e) {
            log.error("Could not resolve URI {}: {}", uri, e.getMessage());
        }

        return new Record[0];
    }
}
