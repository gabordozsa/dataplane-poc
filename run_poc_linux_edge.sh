#! /bin/bash


HOSTS=(gabor-4 local)

declare -A HOSTS_PROCS
HOSTS_PROCS=([gabor-4]="poc_server" [local]="poc_client") 

IMG="quay.io/rh-ee-dgabor/dtls_poc:debug-amd64"

OP="$1"

for h in "${HOSTS[@]}"; do
    p=${HOSTS_PROCS[$h]}
    #echo $h:$p
    case "$OP" in
	run)
	    CMD=$(./run_cmd_edge.sh $p linux)
	     [[ $h =~ local|gabor-4 ]] && CMD="sudo  $CMD" 
	     CMD="$h:  $CMD"
	    ;;
	kill)
	    CMD="killall edge_server dtls_forwarder edge_client"
	    [[ $h == "local" ]] || CMD="ssh $h $CMD"
	    ;;
	copy)
	    CMD="scp -r certs build/edge build/dtls_forwarder $h:"
	    [[ $h == "local" ]] && CMD=""
	    ;;
	route)
	    echo "edge server: sudo ip route add 10.8.0.0/24 dev tun1"
	    echo "edge client: sudo ip route add 10.9.0.0/24 dev tun0"
		exit 0
	    ;;
	*)
	    echo "Unknown command"
	    exit 1
	    ;;
    esac 
    echo $CMD
    [[ $OP != "run" ]] && eval $CMD
done
