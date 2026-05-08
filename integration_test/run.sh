#!/bin/bash
#********************************************************************************
# Copyright (c) 2022 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License 2.0 which is available at
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#*******************************************************************************/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r "${SCRIPT_DIR}"/requirements.txt


DATABROKER_IMAGE=${DATABROKER_IMAGE:-"ghcr.io/eclipse-kuksa/kuksa-databroker:0.6.1"}
DATABROKER_ADDRESS=${DATABROKER_ADDRESS:-"127.0.0.1:55555"}
CONTAINER_PLATFORM=${CONTAINER_PLATFORM:-"linux/amd64"}
DATABROKER_PORT=$(echo "${DATABROKER_ADDRESS}" | cut -d: -f2)

VSS_DATA_DIR="$SCRIPT_DIR/../data"

echo "Starting databroker container (\"${DATABROKER_IMAGE}\") in insecure mode, requesting platform (\"${CONTAINER_PLATFORM}\")"

# Pull the image with retries to handle transient registry unavailability
MAX_PULL_RETRIES=5
PULL_RETRY_DELAY=10
for attempt in $(seq 1 ${MAX_PULL_RETRIES}); do
    if docker pull --platform "${CONTAINER_PLATFORM}" "${DATABROKER_IMAGE}"; then
        break
    fi
    if [ "${attempt}" -eq "${MAX_PULL_RETRIES}" ]; then
        echo "ERROR: Failed to pull image after ${MAX_PULL_RETRIES} attempts"
        exit 1
    fi
    echo "Pull attempt ${attempt} failed, retrying in ${PULL_RETRY_DELAY}s..."
    sleep "${PULL_RETRY_DELAY}"
done

RUNNING_IMAGE=$(
    docker run -d -v ${VSS_DATA_DIR}:/data -p 55555:55555 --rm  --platform ${CONTAINER_PLATFORM} ${DATABROKER_IMAGE} --metadata data/vss-core/vss_release_6.0.json --insecure --enable-databroker-v1
)

if [ -z "${RUNNING_IMAGE}" ]; then
    echo "ERROR: Failed to start databroker container"
    exit 1
fi

# Wait for the databroker to be ready before running the tests
echo "Waiting for databroker to be ready on port ${DATABROKER_PORT}..."
MAX_WAIT=60
WAITED=0
until bash -c "echo >/dev/tcp/127.0.0.1/${DATABROKER_PORT}" 2>/dev/null; do
    if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
        echo "ERROR: Databroker did not become ready within ${MAX_WAIT}s"
        docker stop "${RUNNING_IMAGE}"
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
echo "Databroker is ready (waited ${WAITED}s)"

python3 -m pytest -v "${SCRIPT_DIR}/test_databroker.py"

RESULT=$?

echo "Stopping databroker container"

docker stop ${RUNNING_IMAGE}

exit $RESULT
