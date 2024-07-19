MTA-STS
=======
By **Vlad Marian** *<vmarian@mimecast.com>*


Overview
--------
<img align="right" width="200" height="200" src="doc/logo.png">
SMTP MTA Strict Transport Security

This is a Java implementation of MTA-STS with support for TLSRPT record fetching.

The libray does not provide a production ready trust manager or policy cache.
A X509TrustManager implementation needs to be provided and should enable revocation checks.
An abstract PolicyCache is provided to aid in integrating with your cloud cache. 

This project can be compiled into a runnable JAR.
A CLI interface is implemented.


Best practices
--------------
The following validations are off by default:
- `Require HTTPS response Content-Type as text/plain.`

In practice we see policis that will not have it or have a different value.

- `Require policy line endings as CRLF.`

While the policy states: `This resource contains the following CRLF-separated key/value pairs`
but in the ABNF you see: `sts-policy-term          = LF / CRLF`


Contributions
-------------
Contributions of any kind (bug fixes, new features...) are welcome!
This is a development tool and as such it may not be perfect and may be lacking in some areas.

Certain future functionalities are marked with TODO comments throughout the code.
This however does not mean they will be given priority or ever be done.

Any merge request made should align to existing coding style and naming convention.
Before submitting a merge request please run a comprehensive code quality analysis (IntelliJ, SonarQube).

Read more [here](contributing.md).


Disclosure
----------
This project makes use of sample passwords as needed for testing and demonstration purposes.

- avengers - Test keystore password that contains a single entry issued to Tony Stark. (Easter egg)

**These passwords are not in use within Mimecast production environments.**


RFC Excerpts
------------
- [MTA-STS](doc/mta-sts.md)
- [TLSRPT](doc/tlsrpt.md)


Usage
-----
- [Library usage](doc/lib.md)
- [CLI usage](doc/cli.md)


Guidelines
----------
- [Contributing](contributing.md)
- [Code of conduct](code_of_conduct.md)
