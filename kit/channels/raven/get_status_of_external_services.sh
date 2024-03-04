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
# Get status of external (not running in a RACE node) services required by channel.
# Intent is to ensure that the channel will be functional if a RACE deployment
# were to be started and connections established
#
# Note: For Two Six Indirect Links, need to check the status of the two six whiteboard
#
# Arguments:
# -h, --help
#     Print help and exit
#
# Example Call:
#    bash get_status_of_external_services.sh \
#        {--help}
# -----------------------------------------------------------------------------


###
# Helper functions
###


# Load Helper Functions
BASE_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) >/dev/null 2>&1 && pwd)
. ${BASE_DIR}/helper_functions.sh


###
# Arguments
###


# Parse CLI Arguments
while [ $# -gt 0 ]
do
    key="$1"

    case $key in
        -h|--help)
        echo "Example Call: bash get_status_of_external_services.sh"
        exit 1;
        ;;
        *)
        formatlog "ERROR" "unknown argument \"$1\""
        exit 1
        ;;
    esac
done


###
# Main Execution
###


formatlog "INFO" "Getting compose status. email need to be healthy"
docker-compose -p raven-services -f "${BASE_DIR}/docker-compose.yml" ps

formatlog "INFO" "Getting Expected Container Statuses. email need to be running"
# TODO, once we have health checks, we need to add '--filter "health=healthy"' to the status commands
WHITEBOARD_RUNNING=$(docker ps -q --filter "name=racemail-raven.test" --filter "status=running")
if [ -z "${WHITEBOARD_RUNNING}" ]; then
    echo "Whiteboard is not running but Redis is running, Exit 1"
    exit 1
else 
    echo "Whiteboard and Redis are running, Exit 0"
    exit 0
fi


