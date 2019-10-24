package com.mimecast.mtasts.assets;

import org.xbill.DNS.MXRecord;

/**
 * DNS Record.
 * <p>Wrapper for DNS Java MXRecord.
 *
 * @see MXRecord
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public final class XBillDnsRecord implements DnsRecord {

    /**
     * MXRecord instance.
     */
    private final MXRecord record;

    /**
     * Constructs a new DnsRecord instance.
     *
     * @param record Record instance.
     */
    public XBillDnsRecord(MXRecord record) {
        this.record = record;
    }

    /**
     * Gets name.
     *
     * @return Name string.
     */
    public String getName() {
        return record.getAdditionalName().toString(true);
    }

    /**
     * Gets priority.
     *
     * @return Priority integer.
     */
    public int getPriority() {
        return record.getPriority();
    }
}
