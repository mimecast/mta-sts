package com.mimecast.mtasts.assets;

import com.mimecast.mtasts.client.HttpsResponseMock;
import com.mimecast.mtasts.config.Config;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StsPolicyValidatorTest {

    @Test
    void valid() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertTrue(validator.getErrors().isEmpty());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("", validator.toString());
    }

    @Test
    void notSuccessfull() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(false)
                .setCode(502)
                .setMessage("Bad Gateway")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Response unsuccessfull: Bad Gateway", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Response unsuccessfull: Bad Gateway\r\n", validator.toString());
    }

    @Test
    void wrongCode() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(202)
                .setMessage("Accepted")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Response code invalid: 202", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Response code invalid: 202\r\n", validator.toString());
    }

    @Test
    void noBody() {
        StsPolicyValidator validator = new StsPolicyValidator();

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain");

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Response body is empty", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Response body is empty\r\n", validator.toString());
    }

    @Test
    void longBody() {
        StsPolicyValidator validator = new StsPolicyValidator();

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(Stream.generate(() -> "isInvalidPolicy ").limit(4001).collect(Collectors.joining("")));

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Response body is 64016 bytes which is larger than allowed 64000 bytes", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Response body is 64016 bytes which is larger than allowed 64000 bytes\r\n", validator.toString());
    }

    @Test
    void noHandshake() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(false)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/plain")
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Handshake not done", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Handshake not done\r\n", validator.toString());
    }

    @Test
    void noHeader() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(true)
                .setPeerCertificates(new ArrayList<>())
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Header Content-Type not found", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Header Content-Type not found\r\n", validator.toString());
    }

    @Test
    void wrongHeader() {
        StsPolicyValidator validator = new StsPolicyValidator();

        String policyBody = "version: STSv1\r\n" +
                "mode: enforce\r\n" +
                "mx: *.mimecast.com\r\n" +
                "max_age: 86400\r\n";

        HttpsResponseMock httpsResponse = new HttpsResponseMock()
                .setSuccessful(true)
                .setCode(200)
                .setMessage("OK")
                .setHandshake(false)
                .setPeerCertificates(new ArrayList<>())
                .putHeader("Content-Type", "text/html")
                .setBody(policyBody);

        validator.getPolicy(httpsResponse, new Config());

        assertEquals("Handshake not done", validator.getErrors().get(0));
        assertEquals(1, validator.getErrors().size());
        assertTrue(validator.getWarnings().isEmpty());
        assertEquals("Errors:\r\n" +
                "Handshake not done\r\n", validator.toString());
    }
}
