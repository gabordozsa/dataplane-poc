#! /bin/bash

BUILD=dtls_poc

#ARCH=arm64
ARCH=amd64

#TAG=latest-$ARCH
TAG=debug-$ARCH

REGISTRY=quay.io/rh-ee-dgabor

docker buildx build --load -t $BUILD:$TAG --platform linux/$ARCH -f Dockerfile  .
docker tag $BUILD:$TAG  $REGISTRY/$BUILD:$TAG
docker push $REGISTRY/$BUILD:$TAG