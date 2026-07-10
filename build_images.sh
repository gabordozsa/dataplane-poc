#! /bin/bash

BUILD=dtls_poc

ARCH=arm64
#ARCH=amd64

TAG=latest-$ARCH

REGISTRY=quay.io/rh-ee-dgabor

docker build -t $BUILD:$TAG --build-arg="PLATFORM=$ARCH" -f Dockerfile  .
docker tag $BUILD:$TAG  $REGISTRY/$BUILD:$TAG
docker push $REGISTRY/$BUILD:$TAG