#!/usr/bin/env bash

# 
# Copyright 2023 Two Six Technologies
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

# -----------------------------------------------------------------------------
# This script starts a docker container that will be used for building the RACE
# plugin. By default, the build_artifacts.sh script is run inside the docker container.
# Optionally, additional arguments to docker run may be provided, or a different
# command may be run instead of build (such as a shell).
# -----------------------------------------------------------------------------

set -e
CALL_NAME="$0"


###
# Helper functions
###


# Load Helper Functions
CURRENT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) >/dev/null 2>&1 && pwd)
. ${CURRENT_DIR}/helper_functions.sh


###
# Arguments
###


# Override Args
DOCKER_ARGS=""
BUILD_ARGS=""

FILEPATH="$(pwd)"

# Docker Image Values
RACE_CONTAINER_REGISTRY="ghcr.io/tst-race"
RACE_PROJECT="race-core"
RACESDK_IMAGE_NAME="race-sdk"
LOCAL=false

# Version values
RACESDK_TAG="2.6.0" # branch/tag

COMMAND="./build_artifacts.sh"

while [ $# -gt 0 ]
do
    key="$1"


    case $key in
        -a|--args)
        DOCKER_ARGS="$2"
        shift
        shift
        ;;
        --args=*)
        DOCKER_ARGS="${1#*=}"
        shift
        ;;

        -b|--build-args)
        BUILD_ARGS="$2"
        shift
        shift
        ;;
        --build-args=*)
        BUILD_ARGS="${1#*=}"
        shift
        ;;

        -c|--command)
        COMMAND="$2"
        shift
        shift
        ;;
        --command=*)
        COMMAND="${1#*=}"
        shift
        ;;


        -f|--filepath)
        FILEPATH="$2"
        shift
        shift
        ;;
        --filepath=*)
        FILEPATH="${1#*=}"
        shift
        ;;

        --tag)
        if [ $# -lt 2 ]; then
            formatlog "ERROR" "missing RACE version number" >&2
            exit 1
        fi
        RACESDK_TAG="$2"
        shift
        shift
        ;;
        --tag=*)
        RACESDK_TAG="${1#*=}"
        shift
        ;;

        -l|--local)
        LOCAL=true
        shift
        ;;

        -p|--project)
        RACE_PROJECT="$2"
        shift
        shift
        ;;

        --command=*)
        COMMAND="${1#*=}"
        shift
        ;;

        -h|--help)
        printf "%s" "${HELP}"
        exit 1;
        ;;

        --*)
        echo "${1#*=}"
        shift
        break
        ;;
        *)
        formatlog "ERROR" "${CALL_NAME} unknown argument \"$1\""
        exit 1
        ;;
    esac
done

###
# Main Execution
###


if [ "${LOCAL}" = true ]; then
    RACE_COMPILE_IMAGE="${RACESDK_IMAGE_NAME}:${RACESDK_TAG}"
else
    RACE_COMPILE_IMAGE="${RACE_CONTAINER_REGISTRY}/${RACE_PROJECT}/${RACESDK_IMAGE_NAME}:${RACESDK_TAG}"
    docker pull "${RACE_COMPILE_IMAGE}"
fi

formatlog "INFO" "Using image ${RACE_COMPILE_IMAGE}"
docker inspect -f '{{ .Created }}' "${RACE_COMPILE_IMAGE}"

formatlog "INFO" "Running Docker Container and Running Build Command"
docker run --rm -it \
    -v "${FILEPATH}":/code \
    -w /code \
    --name "kit_builder_raven" \
    ${DOCKER_ARGS} \
    "${RACE_COMPILE_IMAGE}" \
    "${COMMAND}" ${BUILD_ARGS} "$@"
