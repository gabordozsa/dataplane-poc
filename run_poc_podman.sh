#! /bin/bash


HOSTS=(gabor-4 gabor-3 gabor-2 local)

declare -A HOSTS_PROCS
HOSTS_PROCS=([gabor-4]="poc_server" [gabor-3]="poc_forward_2" [gabor-2]="poc_forward_1" [local]="poc_client") 

IMG="quay.io/rh-ee-dgabor/dtls_poc:debug-amd64"

OP="$1"

for h in "${HOSTS[@]}"; do
    p=${HOSTS_PROCS[$h]}
    echo $h:$p
    case "$OP" in
	run)
	    CMD=$(./run_cmd.sh $p podman)
	    ;;
	rm)
	    CMD="podman rm -f $p"
	    ;;
	pull)
	    CMD="podman pull $IMG"
	    ;;
	*)
	    echo "Unknown podman command"
	    exit 1
	    ;;
    esac 
    [[ $h == "local" ]] || CMD="ssh $h $CMD"
    echo $CMD
    eval $CMD
done
