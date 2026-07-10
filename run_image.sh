#! /bin/bash

CLIENT_IP=192.168.100.1
CLIENT_TUN_IP=10.8.0.1

SERVER_IP=192.168.100.2
SERVER_PORT=4433
SERVER_TUN_IP=10.9.0.254

FORWARD_1_IP=192.168.100.3
FORWARD_2_IP=192.168.100.4
FORWARD_IN_PORT=5000
FORWARD_OUT_PORT=5010

PROC=$1

case $PROC in
    server)
        CMD="./edge_server ${SERVER_PORT} certs/server_cert.pem certs/server_key.pem ${SERVER_TUN_IP}"
        ;;
    forward_1)
        CMD="./dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${FORWARD_2_IP} ${FORWARD_IN_PORT}"
        ;;
    forward_2)
        CMD="./dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${SERVER_IP} ${SERVER_PORT}"
        ;;
    client)
        CMD="edge_client ${FORWARD_1_IP} ${FORWARD_IN_PORT}  ${CLIENT_TUN_IP}"
        ;;
    *)
        echo "Unknown proc name"
        exit 1
esac

IMG=quay.io/rh-ee-dgabor/dtls_poc:latest-amd64

RUN="podman -d --security-opt="seccomp=unconfined" $IMG $CMD"
echo $RUN
#eval $RUN
