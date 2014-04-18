#"/bin/bash

exec gnutls-serv --echo --udp --disable-client-cert --heartbeat --x509cafile=x509-ca.pem --x509keyfile=x509-server-key.pem --x509certfile=x509-server.pem --port=4433
