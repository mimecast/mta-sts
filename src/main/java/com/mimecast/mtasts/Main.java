package com.mimecast.mtasts;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.mimecast.mtasts.assets.DnsRecord;
import com.mimecast.mtasts.assets.StsPolicy;
import com.mimecast.mtasts.client.OkHttpsPolicyClient;
import com.mimecast.mtasts.client.XBillDnsRecordClient;
import com.mimecast.mtasts.exception.BadPolicyException;
import com.mimecast.mtasts.exception.BadRecordException;
import com.mimecast.mtasts.exception.NoRecordException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.validator.ValidatorException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * CLI runnable.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
@SuppressWarnings({"squid:S106","squid:S1192","squid:S3776"})
public class Main {

    /**
     * StrictTransportSecurity instance.
     * <p>Isolated for testing.
     */
    static StrictTransportSecurity strictTransportSecurity;

    /**
     * Main runnable.
     *
     * @param args String array.
     */
    public static void main(String[] args) throws InstantiationException, NoSuchAlgorithmException, KeyStoreException {
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        Security.setProperty("ocsp.enable", "true");

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        strictTransportSecurity = new StrictTransportSecurity(
                new XBillDnsRecordClient(),
                new OkHttpsPolicyClient((X509TrustManager) trustManagerFactory.getTrustManagers()[0]));

        new Main(args);
    }

    /**
     * Constructs a new Main instance.
     *
     * @param args String array.
     */
    Main(String[] args) {
        // Disable logging.
        Configurator.setAllLevels(LogManager.getRootLogger().getName(), Level.OFF);

        // Parse options.
        Options options = options();
        Optional<CommandLine> opt = parseArgs(options, args);

        if (opt.isPresent()) {
            CommandLine cmd = opt.get();

            // Run.
            if (cmd.hasOption("domain")) {
                String domain = cmd.getOptionValue("domain");

                try {
                    // Get policy.
                    Optional<StsPolicy> optional = strictTransportSecurity.getPolicy(domain);
                    if (optional.isPresent()) {
                        StsPolicy policy = optional.get();

                        // Match MX.
                        if (cmd.hasOption("mx")) {
                            log("Match MX");
                            log("- - - - - - - - - - - - - - - - - - - - - - - - -");
                            log("MX:\t\t" + cmd.getOptionValue("mx"));
                            log("Match:\t" + policy.matchMx(cmd.getOptionValue("mx")));
                            log("- - - - - - - - - - - - - - - - - - - - - - - - -");
                        }

                        // Policy details JSON.
                        if (cmd.hasOption("json") || cmd.hasOption("file")) {
                            Map<String, Object> jsonMap = getJson(policy);

                            // Print.
                            if (cmd.hasOption("json")) {
                                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                                log(gson.toJson(jsonMap));
                            }

                            // Save to file.
                            if (cmd.hasOption("file")) {
                                saveJson(jsonMap, cmd.getOptionValue("file"));
                            }
                        }
                    }

                } catch (ValidatorException | NoRecordException | BadRecordException | BadPolicyException e) {
                    log("Ran into a problem: " + e.getMessage());
                }
            }

            // Show usage.
            else {
                optionsUsage(options);
            }
        }

        // Show usage.
        else {
            optionsUsage(options);
        }
    }

    /**
     * Gets policy data as JSON.
     *
     * @param policy StsPolicy instance.
     * @return JSON map.
     */
    private Map<String, Object> getJson(StsPolicy policy) {
        Map<String, Object> json = new HashMap<>();

        // MTA-STS Policy.
        Map<String, String> stsPolicy = new HashMap<>();
        stsPolicy.put("version", policy.getVersion());
        stsPolicy.put("mode", policy.getMode().toString());
        stsPolicy.put("mx", policy.getMxMasks().stream().map(String::valueOf).collect(Collectors.joining(", ")));
        stsPolicy.put("max_age", String.valueOf(policy.getMaxAge()));
        stsPolicy.put("valid", String.valueOf(policy.isValid()));
        json.put("stsPolicy", stsPolicy);

        // MTA-STS Record.
        Map<String, String> stsRecord = new HashMap<>();
        stsRecord.put("location", "_mta-sts." + policy.getRecord().getDomain());
        stsRecord.put("version", policy.getRecord().getVersion());
        stsRecord.put("id", policy.getRecord().getId());
        stsRecord.put("valid", String.valueOf(policy.getRecord().isValid()));
        json.put("stsRecord", stsRecord);

        // TLSRPT Record.
        Map<String, String> tlsRecord = new HashMap<>();
        tlsRecord.put("version", policy.getReport().getVersion());
        tlsRecord.put("rua", policy.getReport().getRua().stream().map(String::valueOf).collect(Collectors.joining(", ")));
        tlsRecord.put("valid", String.valueOf(policy.getReport().isValid()));
        json.put("tlsRecord", tlsRecord);

        // MX Records.
        List<Map<String, String>> mxList = new ArrayList<>();
        for (DnsRecord record : strictTransportSecurity.getMxRecords(policy.getRecord().getDomain())) {
            Map<String, String> mx = new HashMap<>();
            mx.put("priority", String.valueOf(record.getPriority()));
            mx.put("entry", record.getName());
            mxList.add(mx);
        }
        json.put("mxList", mxList);

        // Peer certificate chain.
        if (policy.getPeerCertificates() != null) {
            List<Map<String, Object>> chain = new ArrayList<>();
            for (Certificate c : policy.getPeerCertificates()) {
                try {
                    X509Certificate certificate = (X509Certificate) c;
                    HashMap<String, Object> cert = new HashMap<>();
                    cert.put("notBefore", certificate.getNotBefore());
                    cert.put("notAfter", certificate.getNotAfter());
                    cert.put("serialNumber", certificate.getSerialNumber());
                    cert.put("algorithm", certificate.getSigAlgName());
                    cert.put("type",  certificate.getType());
                    cert.put("version",  certificate.getVersion());

                    cert.put("subjectDName: ", certificate.getSubjectDN().getName());
                    cert.put("subjectAlternativeNames", certificate.getSubjectAlternativeNames());
                    cert.put("subjectKeyIdentifier", new String(Hex.encodeHex(certificate.getExtensionValue("2.5.29.14"))));

                    cert.put("issuerDName", certificate.getIssuerDN().getName());
                    cert.put("issuerKeyIdentifier", new String(Hex.encodeHex(certificate.getExtensionValue("2.5.29.19"))));
                    chain.add(cert);
                } catch (CertificateParsingException e) {
                    log("Error getting certificate details: " + e.getMessage());
                }
            }
            json.put("certificateChain", chain);

            // Warnings and errors.
            json.put("warnings", policy.getValidator().getWarnings());
            json.put("errors", policy.getValidator().getErrors());
        }

        return json;
    }

    /**
     * Saves JSON to file.
     *
     * @param jsonMap JSON map.
     * @param filePath File path.
     */
    private void saveJson(Map<String, Object> jsonMap, String filePath) {
        try (Writer writer = new FileWriter(filePath)) {
            new GsonBuilder().create().toJson(jsonMap, writer);
        } catch (IOException e) {
            log("Error writing JSON: " + e.getMessage());
        }
    }

    /**
     * CLI options.
     * <p>Listing order will be alphabetical.
     *
     * @return Options instance.
     */
    private Options options() {
        Options options = new Options();
        options.addOption("d", "domain", true, "Domain");
        options.addOption("m", "mx", true, "MX to match against policy MX masks");
        options.addOption("j", "json", false, "Show policy details as JSON");
        options.addOption("f", "file", true, "Write policy details to JSON file");
        return options;
    }

    /**
     * CLI usage.
     *
     * @param options CLI options.
     */
    private void optionsUsage(Options options) {
        log("java -jar mta-sts.jar");
        log(" SMTP MTA Strict Transport Security");
        log("");

        StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);

        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(pw, 80, " ", "", options, formatter.getLeftPadding(), formatter.getDescPadding(), "", true);

        pw.flush();

        log(out.toString());
        log("");
    }

    /**
     * Parser for CLI arguments.
     *
     * @param options Options instance.
     * @param args    Arguments string array.
     * @return Optional of CommandLine.
     */
    private Optional<CommandLine> parseArgs(Options options, String[] args) {
        CommandLine cmd = null;

        try {
            cmd = new DefaultParser().parse(options, args, true);
        } catch (Exception e) {
            log("Ran into a problem: " + e.getMessage());
        }

        return Optional.ofNullable(cmd);
    }

    /**
     * Logging wrapper.
     *
     * @param string String.
     */
    void log(String string) {
        System.out.println(string);
    }
}
