TLSRPT
======

SMTP TLS Reporting

TLSRPT defines a reporting schema that covers failures in routing, DNS resolution, STARTTLS negotiation;
policy validation errors for both DANE [RFC6698] and MTA-STS [RFC8461];
and a standard TXT record that recipient domains can use to indicate where reports should be sent.

The report can also serve as a heartbeat to indicate that systems are successfully negotiating TLS.


Terminology
-----------
The key words "MUST", "MUST NOT", "MAY", "SHOULD", "SHOULD NOT" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.


Worlflow
--------

A TXT record is used for advertising TLSRPT support.

Policy consists of the following directives:

-  "v": This document defines version 1 of TLSRPT, for which this value MUST be equal to "TLSRPTv1".
Other versions may be defined in later documents.

-  "rua": A URI specifying the endpoint to which aggregate information about policy validation results should be sent.
Two URI schemes are supported: "mailto" and "https".  As with DMARC [RFC7489], 
the Policy Domain can specify a comma-separated list of URIs.

Report submitters MAY ignore certificate validation errors when submitting reports via HTTPS POST.

Sending MTAs MUST deliver reports despite any TLS-related failures and SHOULD NOT include this SMTP session in the next report.

Reports sent via SMTP MUST contain a valid DomainKeys Identified Mail (DKIM) [RFC6376] signature by the reporting domain.
Reports lacking such a signature MUST be ignored by the recipient.


TLSRPT DNS TXT record:
----------------------

The record supports the ability to declare more than one rua, and if there exists more than one,
the reporter MAY attempt to deliver to each of the supported rua destinations.

A receiver MAY opt to only attempt delivery to one of the endpoints;
however, the report SHOULD NOT be considered successfully delivered until one of the endpoints accepts delivery of the report.

- If multiple TXT records for "_smtp._tls" are returned by the resolver,
records that do not begin with "v=TLSRPTv1;" are discarded.

- If the number of resulting records is not one, senders MUST assume the recipient domain does not implement TLSRPT.

Report Using MAILTO:

    _smtp._tls.example.com.   300   IN   TXT   "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"

Report Using HTTPS:

    _smtp._tls.example.com.   300   IN   TXT   "v=TLSRPTv1; rua=https://tlsrpt.example.com/v1"

Reports Using MULTIPLE:

    _smtp._tls.example.com.   300   IN   TXT   "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,mailto:tlsrpt@example.net,"
    _smtp._tls.example.com.   300   IN   TXT   "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://tlsrpt.example.com/v1"
    _smtp._tls.example.com.   300   IN   TXT   "v=TLSRPTv1; rua=https://tlsrpt.example.com/v1,https://tlsrpt.example.net/v1"


DKIM DNS TXT record:
--------------------

The DKIM TXT record SHOULD contain the appropriate service type declaration, "s=tlsrpt" as for [RFC6376] Section 3.6.1.
If not present, the receiving system MAY ignore reports lacking that service type.

DKIM signatures MUST NOT use the "l=" attribute to limit the body length used in the signature.
This ensures attackers cannot append extraneous or misleading data to a report without breaking the signature.

Sample DKIM record:

    dkim_selector._domainkey.example.com.   300   IN   TXT   "v=DKIM1; k=rsa; s=tlsrpt; p=Mlf4qwSZfase4fa=="


JSON Report Schema:
-------------------

The report SHOULD cover a full day, from 00:00-24:00 UTC.
This should allow for easier correlation of failure events.
To avoid unintentionally overloading the system processing the reports,
the reports should be delivered after some delay, perhaps several hours.

### Result Types

The list of result types will start with the minimal set below and is expected to grow over time based on real-world experience.

#### Negotiation Failures:
- starttls-not-supported
- certificate-host-mismatch
- certificate-expired
- certificate-not-trusted
- validation-failure;

#### Policy Failures for DANE:
- tlsa-invalid
- dnssec-invalid
- dane-required;

#### Policy Failures for MTA-STS:
- sts-policy-fetch-error
- sts-policy-invalid
- sts-webpki-invalid;

#### General Failure:
- validation-failure


        {
          "organization-name": "The organization responsible for the report.",
          "contact-info": "Contact information for one or more responsible parties for the contents of the report.",
          "report-id": "A unique identifier for the report.",
          "date-range": {
            "start-datetime": "Internet Date/Time Format [RFC3339] Section 5.6, UTC 00:00.",
            "end-datetime": "Internet Date/Time Format [RFC3339] Section 5.6, UTC 24:00."
          },
          "policies": [
            {
              "policy": {
                "policy-type": "One of three valid choices so far: tlsa, sts and no-policy-found.",
                "policy-string": "An encoding of the applied policy as a JSON array of strings.",
                "policy-domain": "The Policy Domain against which the MTA-STS or DANE policy is defined.",
                "mx-host": "For sts: The pattern of MX hostnames from the applied policy provided as a JSON array of strings."
              },
              "summary": {
                "total-successful-session-count": "The aggregate count of successfully negotiated TLS-enabled connections.",
                "total-failure-session-count": "The aggregate count of failures to negotiate a TLS-enabled connection."
              },
              "failure-details": [
                {
                  "result-type": "As listed above.",
                  "sending-mta-ip": "The IP address of the Sending MTA.",
                  "receiving-mx-hostname": "The hostname of the receiving MTA MX.",
                  "receiving-mx-helo": "The HELO or EHLO string from the banner.",
                  "receiving-ip": "The destination IP address that was resolved from the MX for the outbound session.",
                  "failed-session-count": "The number of (attempted) sessions that match the relevant result-type.",
                  "additional-information": "(optional) A URI [RFC3986] to additional information for the result-type.",
                  "failure-reason-code": "A text field to include a TLS-related error code or error message."
                }
              ]
            }
          ]
        }



References
----------
- https://tools.ietf.org/html/rfc8461 MTA-STS
- https://tools.ietf.org/html/rfc8460 TLSRPT
- https://tools.ietf.org/html/rfc6698 DANE
- https://tools.ietf.org/html/rfc7671 DANE UPDATE
- https://tools.ietf.org/html/rfc7672 DANE FOR SMTP
- https://tools.ietf.org/html/rfc6376 DKIM
- https://tools.ietf.org/html/rfc7489 DMARC
