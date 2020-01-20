package com.mimecast.mtasts.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Local DNS Resolver.
 * <p>This provides a static resolver for DNS Java to aid in testing.
 * <p>It has limited capabilities but more than needed for this lib.
 * <p>It can only handle NS, A, MX, PTR and TXT types.
 * <p>Strings should not exceed 255 bytes.
 * <p>A strings should be valid IPv4 addresses.
 * <p>NS, MX and PTR strings should not be empty.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
@SuppressWarnings("squid:S1186")
public class LocalDnsResolver implements Resolver {
    private static final Logger log = LogManager.getLogger(LocalDnsResolver.class);

    /**
     * Static database.
     */
    private static final Map<String, Map<Integer, List<String>>> map = new HashMap<>();

    /**
     * Put entries in database.
     *
     * @param record Record string.
     * @param answer Answer list of strings.
     */
    public static void put(String record, int type, List<String> answer) {
        map.computeIfAbsent(record, k -> new HashMap<>()).put(type, answer);
    }

    /**
     * Lookup record.
     *
     * @param question Record question instance.
     * @return List of Record.
     */
    private List<Record> lookup(Record question) {
        Map<Integer, List<String>> answer = map.get(question.getName().toString(true));
        List<Record> response = new ArrayList<>();

        if (answer != null && !answer.isEmpty()) {
            List<String> records = answer.get(question.getType());

            if (records != null && !records.isEmpty()) {
                try {
                    response = loop(question.getName(), records, question.getType());
                } catch (TextParseException e) {
                    log.error("Record cannot be parsed: {}", e.getMessage());
                } catch (UnknownHostException e) {
                    log.error("Record host could not be resolved: {}", e.getMessage());
                }
            }
        }

        return response;
    }

    /**
     * Loop results and build responses.
     *
     * @param name Record name.
     * @param records List of String records.
     * @return List of Record.
     */
    private List<Record> loop(Name name, List<String> records, int type) throws TextParseException, UnknownHostException {
        List<Record> response = new ArrayList<>();

        switch (type) {
            case Type.NS:
                for (String record : records) {
                    response.add(new NSRecord(name, 1, 300L, new Name(record)));
                }
                break;
            case Type.A:
                for (String record : records) {
                    response.add(new ARecord(name, 1, 300L, InetAddress.getByName(record)));
                }
                break;
            case Type.MX:
                for (String record : records) {
                    response.add(new MXRecord(name, 1, 300L, 1, new Name(record)));
                }
                break;
            case Type.PTR:
                for (String record : records) {
                    response.add(new PTRRecord(name, 1, 300L, new Name(record)));
                }
                break;
            case Type.TXT:
                for (String record : records) {
                    response.add(new TXTRecord(name, 1, 300L, record));
                }
                break;
            default:
                log.fatal("Record type unsupported");
                throw new IllegalArgumentException("Record type unsupported");
        }

        return response;
    }

    /**
     * Resolves DNS queries from the static deque.
     *
     * @param question Record question instance.
     * @return Record answer instance.
     */
    @Override
    public Message send(Message question) {
        Message answer = new Message();
        answer.getHeader().setID(question.getHeader().getID());
        answer.getHeader().setOpcode(question.getHeader().getOpcode());
        answer.addRecord(question.getQuestion(), 0);

        // Answer.
        List<Record> records = lookup(question.getQuestion());
        if (!records.isEmpty()) {
            for (Record record : records) {
                answer.addRecord(record, 1);
            }
        }

        return answer;
    }

    /**
     * Unused.
     */

    @Override
    public void setPort(int i) {}

    @Override
    public void setTCP(boolean b) {}

    @Override
    public void setIgnoreTruncation(boolean b) {}

    @Override
    public void setEDNS(int i) {}

    @Override
    public void setEDNS(int i, int i1, int i2, List list) {}

    @Override
    public void setTSIGKey(TSIG tsig) {}

    @Override
    public void setTimeout(int i, int i1) {}

    @Override
    public void setTimeout(int i) {}

    @Override
    public Object sendAsync(Message message, ResolverListener resolverListener) {
        return null;
    }
}
