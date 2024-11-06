package com.mimecast.mtasts;

import com.mimecast.mtasts.cache.MemoryPolicyCache;
import com.mimecast.mtasts.client.XBillDnsRecordClient;
import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.mimecast.mtasts.util.LocalHttpsPolicyClient;

import java.util.ArrayList;
import java.util.List;

/**
 * CLI runnable.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link <a href="http://mimecast.com">Mimecast</a>
 */
final class MainMock extends Main {

    /**
     * Logs list.
     */
    private List<String> logs;

    /**
     * Main runnable.
     * <p>Override StrictTransportSecurity instance with new using HttpsPolicyClientMock instance param.
     *
     * @param args String array.
     * @param port HTTPS mock server port.
     */
    public static List<String> main(String[] args, int port) throws InstantiationException {
        strictTransportSecurity = new StrictTransportSecurity(new XBillDnsRecordClient(), new LocalHttpsPolicyClient(new PermissiveTrustManager(), port), new MemoryPolicyCache());

        MainMock main = new MainMock(args);
        return main.getLogs();
    }

    /**
     * Constructs a new Main instance.
     *
     * @param args String array.
     */
    private MainMock(String[] args) {
        super(args);
    }

    /**
     * Logging wrapper.
     *
     * @param string String.
     */
    @Override
    protected void log(String string) {
        super.log(string);
        if (logs == null) {
            logs = new ArrayList<>();
        }
        logs.add(string);
    }

    /**
     * Gets logs.
     *
     * @return List of String.
     */
    private List<String> getLogs() {
        return logs;
    }
}
