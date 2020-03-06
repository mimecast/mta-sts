package com.mimecast.mtasts.util;

import com.mimecast.mtasts.trust.PermissiveTrustManager;
import com.sun.net.httpserver.Headers; // NOSONAR
import com.sun.net.httpserver.HttpsConfigurator; // NOSONAR
import com.sun.net.httpserver.HttpsServer; // NOSONAR

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

/**
 * Local HTTPS Server.
 * <p>Provides a HTTPS server for use in testing.
 * <p>The server should be started after all path and responses have been put.
 *
 * @author "Vlad Marian" <vmarian@mimecast.com>
 * @link http://mimecast.com Mimecast
 */
public class LocalHttpsServer {

    /**
     * HttpsServer database.
     */
    private static final Map<String, LocalHttpsResponse> map = new HashMap<>();

    /**
     * Put entries in database.
     *
     * @param path     HTTP request path.
     * @param response LocalHttpsResponse instance.
     */
    public static void put(String path, LocalHttpsResponse response) {
        map.put(path, response);
    }

    /**
     * HttpsServer instance.
     */
    private HttpsServer httpServer;

    /**
     * Constructs a new HttpPolicyServerMock instance.
     *
     * @throws IOException               IO exception.
     * @throws NoSuchAlgorithmException  No such algorithm exception.
     * @throws KeyStoreException         Key store exception.
     * @throws CertificateException      Certificate exception.
     * @throws UnrecoverableKeyException Unrecoverable key exception.
     * @throws KeyManagementException    Key management exception.
     */
    public LocalHttpsServer() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        // SSL context.
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");

        // Key manager.
        char[] storePass = "avengers".toCharArray();
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("src/test/resources/keystore.jks"), storePass);
        keyManagerFactory.init(keyStore, storePass);

        // Trust manager.
        TrustManager[] tm = new TrustManager[]{new PermissiveTrustManager()};
        ctx.init(keyManagerFactory.getKeyManagers(), tm, null);

        // Server.
        httpServer = HttpsServer.create(new InetSocketAddress(0), 0);
        httpServer.setHttpsConfigurator(new HttpsConfigurator(ctx));

        for (Map.Entry<String, LocalHttpsResponse> entry : map.entrySet()) {
            String path = entry.getKey();
            LocalHttpsResponse response = entry.getValue();

            httpServer.createContext("/" + path, exchange -> {
                if (response != null && response.getResponseString() != null) {
                    Headers responseHeaders = exchange.getResponseHeaders();
                    responseHeaders.add("Content-Type", response.getContentType());

                    exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.getResponseString().length());
                    exchange.getResponseBody().write(response.getResponseString().getBytes());
                } else {
                    exchange.sendResponseHeaders(HttpURLConnection.HTTP_NOT_FOUND, 0);
                }
                exchange.close();
            });
        }

        httpServer.start();
    }

    /**
     * Gets port number.
     *
     * @return Port number.
     */
    public int getPort() {
        return httpServer.getAddress().getPort();
    }

    /**
     * Stop server.
     */
    public void stop() {
        httpServer.stop(0);
    }
}
