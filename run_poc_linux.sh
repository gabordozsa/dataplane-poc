#! /bin/bash


HOSTS=(gabor-4 gabor-3 gabor-2 local)

declare -A HOSTS_PROCS
HOSTS_PROCS=([gabor-4]="poc_server" [gabor-3]="poc_forward_2" [gabor-2]="poc_forward_1" [local]="poc_client") 

IMG="quay.io/rh-ee-dgabor/dtls_poc:debug-amd64"

OP="$1"

if [[ $OP == "copy" ]]; then
    CMD="scp -r certs edge_server dtls_forwarder edge_client "
fi


for h in "${HOSTS[@]}"; do
    p=${HOSTS_PROCS[$h]}
    #echo $h:$p
    case "$OP" in
	run)
	    CMD=$(./run_cmd.sh $p linux)
	    [[ $h == "local" ]] || CMD="ssh $h $CMD"
	    ;;
	kill)
	    CMD="killall edge_server dtls_forwarder edge_client"
	    [[ $h == "local" ]] || CMD="ssh $h $CMD"
	    ;;
	copy)
	    CMD="scp -r certs build/edge_server build/dtls_forwarder build/edge_client $h:"
	    [[ $h == "local" ]] && CMD=""
	    ;;
	*)
	    echo "Unknown command"
	    exit 1
	    ;;
    esac 
    echo $CMD
    [[ $OP != "run" ]] && eval $CMD
done
