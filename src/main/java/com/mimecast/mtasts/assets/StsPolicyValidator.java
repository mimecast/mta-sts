package com.mimecast.mtasts.assets;

import com.mimecast.mtasts.cache.PolicyCache;
import com.mimecast.mtasts.client.HttpsResponse;
import com.mimecast.mtasts.config.Config;
import com.mimecast.mtasts.stream.LineInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Strict Transport Security Policy Validator.
 * <p>Parser for MTA-STS HTTPS policy file contents.
 * <p>Once constructed all data can be retrieved.
 * <p>Primary scope is to match MX domains against the policy list of MX masks.
 *
 * @link https://tools.ietf.org/html/rfc8461#section-3.2 RFC8461#section-3.2
 *
 * @see StsRecord
 * @see PolicyCache
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class StsPolicyValidator {
    private static final Logger log = LogManager.getLogger(StsPolicyValidator.class);

    /**
     * List of errors.
     */
    private final List<String> errors = new ArrayList<>();

    /**
     * List of warnings.
     */
    private final List<String> warnings = new ArrayList<>();

    /**
     * Gets policy.
     *
     * @param response HttpsResponse instance.
     * @param config Config instance.
     * @return Policy string.
     */
    public String getPolicy(HttpsResponse response, Config config) {
        // Validate required.
        if (!response.isSuccessful()) {
            log("Response unsuccessfull: " + response.getMessage(), true);
        }
        else if (response.getCode() != 200) {
            log("Response code invalid: " + response.getCode(), true);
        }
        else if (response.getBody() == null) {
            log("Response body is empty", true);
        }
        else if (response.getBody().length() > config.getPolicyMaxBodySize()) {
            log("Response body is " + response.getBody().length() + " bytes which is larger than allowed " + config.getPolicyMaxBodySize() + " bytes", true);
        }
        else if (!response.isHandshake()) {
            log("Handshake not done", true);
        }

        // Validate optionals.
        else {
            String contentType = response.getHeader("Content-Type");
            if (contentType == null) {
                log("Header Content-Type not found", config.isRequireTextPlain());
            }
            else if (!contentType.equalsIgnoreCase("text/plain")) {
                log("Header Content-Type invalid: " + contentType, config.isRequireTextPlain());
            }

            return response.getBody();
        }

        return null;
    }

    /**
     * Validate body.
     *
     * @param line Line byte array.
     * @param config Config instance.
     */
    void validateLine(byte[] line, Config config) {
        // Trace logging for debugging.
        if (log.isTraceEnabled()) {
            log.trace("Validate line: {}", new String(line, StandardCharsets.UTF_8));
        }

        if (line.length > 2) {
            int cr = line[line.length - 2];
            int lf = line[line.length - 1];

            if (lf != LineInputStream.CR && lf != LineInputStream.LF) {
                log("Policy EOL not found", config.isRequireCRLF());
            }

            else if (cr != LineInputStream.CR || lf != LineInputStream.LF) {
                log("Policy EOL not CRLF", config.isRequireCRLF());
            }
        }
        else {
            log("Policy does not support empty lines", config.isRequireCRLF());
        }
    }

    /**
     * Gets error.
     *
     * @return Error string.
     */
    public List<String> getErrors() {
        return errors;
    }

    /**
     * Gets warnings.
     *
     * @return List of String.
     */
    public List<String> getWarnings() {
        return warnings;
    }

    /**
     * Adds warning.
     *
     * @param warning String.
     */
    public void addWarning(String warning) {
        warnings.add(warning);
    }

    /**
     * Logs warning or error based on boolean flag.
     *
     * @param string Warning/Error string.
     * @param error Is Error not Warning.
     */
    private void log(String string, boolean error) {
        // Add unique error
        if (error && !errors.contains(string)) {
            log.info("Request validation error: {}", string);
            errors.add(string);
        }

        // Add unique warning
        else if (!error && !warnings.contains(string)) {
            log.info("Request validation warning: {}", string);
            warnings.add(string);
        }
    }

    /**
     * To string.
     *
     * @return Policy string.
     */
    public String toString() {
        StringBuilder string = new StringBuilder();

        if (!errors.isEmpty()) {
            string.append("Errors:").append("\r\n");
            errors.forEach(error -> string.append(error).append("\r\n"));
        }

        if (!warnings.isEmpty()) {
            string.append("Warnings:").append("\r\n");
            warnings.forEach(warning -> string.append(warning).append("\r\n"));
        }

        return string.toString();
    }
}
