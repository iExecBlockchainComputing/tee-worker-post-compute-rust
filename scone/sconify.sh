#!/bin/bash

cd $(dirname $0)

SCONE_IMG_NAME=scone-debug/iexec-sconify-image-unlocked
SCONE_IMG_VERSION=5.9.1

if [ -z "$IMG_FROM" ] || [ -z "$IMG_TO" ] ; then
  echo "IMG_FROM and IMG_TO variables need to be defined"
  exit 1
fi

ARGS=$(sed -e "s'\${IMG_FROM}'${IMG_FROM}'" -e "s'\${IMG_TO}'${IMG_TO}'" sconify.args)
echo $ARGS

SCONE_IMAGE="registry.scontain.com/${SCONE_IMG_NAME}:${SCONE_IMG_VERSION}"

docker run -t --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    ${SCONE_IMAGE} \
        sconify_iexec \
            --cli=${SCONE_IMAGE} \
            --crosscompiler=${SCONE_IMAGE} \
            $ARGS

echo
docker run --rm -e SCONE_HASH=1 $IMG_TO
