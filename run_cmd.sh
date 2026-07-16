#! /bin/bash

CLIENT_IP=10.15.242.173
CLIENT_TUN_IP=10.8.0.1

SERVER_IP=10.16.142.61
SERVER_PORT=4433
SERVER_TUN_IP=10.9.0.254

FORWARD_1_IP=10.14.76.243
FORWARD_2_IP=10.15.229.129
FORWARD_IN_PORT=5000
FORWARD_OUT_PORT=5010

#PLATFORM=podman

PROC="$1"
PLATFORM="$2"

case "$PROC" in
    poc_server)
        CMD="./edge server ${SERVER_TUN_IP} ${SERVER_PORT} certs/server_cert.pem certs/server_key.pem"
	PORTMAP="-p ${SERVER_PORT}:${SERVER_PORT}/udp"
	CAPS="--cap-add=NET_ADMIN,NET_RAW --device /dev/net/tun"
        ;;
    poc_forward_1)
        CMD="./dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${FORWARD_2_IP} ${FORWARD_IN_PORT}"
	PORTMAP="-p ${FORWARD_IN_PORT}:${FORWARD_IN_PORT}/udp"
        ;;
    poc_forward_2)
        CMD="./dtls_forwarder ${FORWARD_IN_PORT} ${FORWARD_OUT_PORT}  certs/forwarder_cert.pem certs/forwarder_key.pem  ${SERVER_IP} ${SERVER_PORT}"
	PORTMAP="-p ${FORWARD_IN_PORT}:${FORWARD_IN_PORT}/udp"
        ;;
    poc_client)
        CMD="./edge client ${CLIENT_TUN_IP} ${FORWARD_IN_PORT}  ${FORWARD_1_IP}"
        CAPS="--cap-add=NET_ADMIN,NET_RAW --device /dev/net/tun"
        ;;
    *)
        echo "Unknown proc name"
        exit 1
esac

#IMG=quay.io/rh-ee-dgabor/dtls_poc:latest-amd64
IMG=quay.io/rh-ee-dgabor/dtls_poc:debug-amd64

case $PLATFORM in
    podman)
	RUN="podman run -d --security-opt="seccomp=unconfined" $CAPS $PORTMAP --name $PROC $IMG $CMD"
	;;
    linux)
	RUN=$CMD
	;;
    *)
	echo "Unknown platform"
	exit 1
	;;
esac

echo $RUN

