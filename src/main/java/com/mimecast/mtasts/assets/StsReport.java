package com.mimecast.mtasts.assets;

import org.apache.commons.validator.routines.EmailValidator;
import org.apache.commons.validator.routines.UrlValidator;

import java.util.ArrayList;
import java.util.List;

/**
 * Strict Transport Security Report.
 * <p>Parser for TLSRPT DNS TXT record contents.
 * <p>Once constructed all data can be retrieved.
 * <p>Primary scope is for rua fetching for reporting HTTPS and/or mailto:.
 *
 * @link https://tools.ietf.org/html/rfc8460#section-3.1 RFC8460#section-3.1
 *
 * @see StsPolicy
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public final class StsReport extends StsDnsTxt {

    /**
     * Rua list.
     */
    private final List<String> rua = new ArrayList<>();

    /**
     * Constructs a new StsReport instance.
     * <p>The parser will not except on parsing so it should always be validated via the provided isValid() method.
     *
     * @param record Record string.
     */
    public StsReport(String record) {
        super(record);
        parseRua();
    }

    /**
     * Parse rua token.
     * <p>We do this immediatly so we may properly validate.
     */
    private void parseRua() {
        String token = tokens.get("rua");
        if (token != null) {
            for (String entry : token.split(",")) {
                String low = entry.toLowerCase();
                if (
                    (low.startsWith("mailto:") && EmailValidator.getInstance(false).isValid(low.replace("mailto:", ""))) ||
                    (low.startsWith("https://") && UrlValidator.getInstance().isValid(entry))
                    ) {

                    rua.add(entry);
                }
            }
        }
    }

    /**
     * Is valid.
     * <p>Checks both v (version) and ID are declared.
     * <p>Only version 1 accepted but matched case insensitive to be more relaxed.
     *
     * @return Boolean.
     */
    public boolean isValid() {
        return tokens.containsKey("v") && tokens.get("v").equalsIgnoreCase("TLSRPTv1") && !rua.isEmpty();
    }

    /**
     * Gets rua.
     *
     * @return List of String.
     */
    public List<String> getRua() {
        return rua;
    }
}
