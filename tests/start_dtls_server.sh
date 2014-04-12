#"/bin/bash

exec ./openssl_vuln s_server -no_ssl2 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -dtls1 -msg -key x509-server-key.pem -cert x509-server.pem -CAfile x509-ca.pem
