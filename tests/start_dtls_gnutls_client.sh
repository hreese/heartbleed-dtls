#"/bin/bash

exec gnutls-cli --no-ca-verification --heartbeat --noticket --udp --port=4433 localhost
