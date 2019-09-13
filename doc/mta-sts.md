MTA-STS
=======

SMTP MTA Strict Transport Security

Designed to protect against the opportunistic nature of STARTTLS and MITM attacks that can remove STARTLS advertising to force plain text exchange.

This is done by using a combination of DNS TXT record and well-known HTTPS text/plain file to enforce TLS 1.2 or newer to existing MX servers.

The key security functionality to defeat MITM attacks is the secure nature of certificates aside from known breaches of authorities.


Terminology
-----------
The key words "MUST", "MAY" and "SHOULD" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.


Worlflow
--------

A TXT record is used for advertising MTA-STS support.
Before establishing a connection a client MUST check for the record presence.

Policy consists of the following directives:

-  "v": This document defines version 1 of STS, for which this value MUST be equal to "STSv1".
Other versions may be defined in later documents.

-  "id": A short string used to track policy updates.
This string MUST uniquely identify a given instance of a policy, such that senders can determine when the policy has been
updated by comparing to the "id" of a previously seen policy. There is no implied ordering of "id" fields between revisions.

If record is present the policy file would be downloaded via HTTPS.
The server certificate MUST be validated and MAY be checked for revocation.
If everything check the data can be cached using the ID and domain as keys.

MX records resolved MUST be checked against the list of MX entries within the file.
This list may contain wildcard entries so this needs to be factored in the validation.
Given validation passes a connection can be established.

The EHLO response of the server MUST advertise STARTTLS or else the connection MUST be terminated.
TLS handshake MUST only support TLSv1.2 or newer.


Considerations
--------------

To allow rapid changes to long lived policies MTA's MUST check the DNS TXT record before a connection
even when having a cache entry for the domain.
If the ID has changed the cache should be invalidated and the policy file re-downloaded.

If multiple TXT records for "_mta-sts" are returned by the resolver, records that do not begin with "v=STSv1;" are discarded.
If the number of resulting records is not one, or if the resulting record is syntactically invalid,
senders MUST assume the recipient domain does not have an available MTA-STS Policy and skip the remaining steps of policy discovery.

If a MX validation fails or STARTTLS is not advertised senders SHOULD try the next MX rather than re-queueing.

If a valid TXT record is found but no policy can be fetched via HTTPS (for any reason),
and there is no valid (non-expired) previously cached policy,
senders MUST continue with delivery as though the domain has not implemented MTA-STS.

Conversely, if no "live" policy can be discovered via DNS or fetched via HTTPS,
but a valid (non-expired) policy exists in the sender's cache, the sender MUST apply that cached policy.

Max lifetime of the policy SHOULD be plaintext non-negative integer seconds, maximum value of 31557600.
To mitigate the risks of attacks at policy refresh time,
it is expected that this value typically be in the range of weeks or greater.

MTAs SHOULD proactively refresh cached policies before they expire; a suggested refresh frequency is once per day.

When sending mail via a "smart host" -- an administratively configured intermediate SMTP relay,
which is different from the message recipient's server as determined from DNS -- compliant senders MUST
treat the smart host domain as the Policy Domain for the purposes of policy discovery and application. 


Specifications
--------------

1. DNS TXT record:

        _mta-sts.example.com.   300   IN   TXT   "v=STSv1; id=aca9f86d663;"

2. HTTPS TXT file:

        https://mta-sts.<DOMAIN>/.well-known/mta-sts.txt

  - File MUST be downloaded over HTTPS.
  - Server certificate MUST be valid and trusted.
  - Certificate revocation check MAY be done.

        version: STSv1
        mode: testing
        mx: mx1.example.com
        mx: mx2.example.com
        mx: *.example.com
        max_age: 86400

  - File MUST contain the following variables formatted as above:
    - version: STSv1 - The only version supported at the time of writing.
    - mode: enforce, testing or none
      - enforce: All validations MUST pass
      - testing: Delivery may proceed regardless of validation failures.
      - none: Disabled
    - max_age: Policy lifetime. Min/max: 604800/31557600 Hard min: 86400
    - mx: List of MX servers for the domain, wildcard entries are permitted.


References
----------
- https://tools.ietf.org/html/rfc8461 MTA-STS
- https://tools.ietf.org/html/rfc8460 TLSRPT
