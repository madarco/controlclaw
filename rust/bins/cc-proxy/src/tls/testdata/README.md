Test-only CAs for `tls/ca.rs` (RSA 2048, made with `openssl genrsa` and `openssl req -x509` as
`gen-ca.sh` does): the same CA with its key in PKCS#8 (`ca-pkcs8.pem`, OpenSSL 3) and PKCS#1
(`ca-pkcs1.pem`, older OpenSSL). Never used outside the unit tests.

`chrome-153-hello.bin` and `chrome-153-h2-preface.bin`: the built-in browser profile (`tls/chrome.rs`), captured from Google Chrome 153.0.8010.52 headless against `https://www.example.com/` mapped to a local listener. The first is the ClientHello records as sent; the second the start of its HTTP/2 connection (preface, SETTINGS, WINDOW_UPDATE, first HEADERS). Nothing secret: an ephemeral key share and a request for example.com.
