#"/bin/bash

exec openssl s_client -no_ssl2 -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -dtls1 -no_ticket -connect localhost:4433
