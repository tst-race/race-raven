#!/usr/bin/env python3
"""
Purpose:
    Generate the plugin configs based on a provided range config and save 
    config files to the specified config directory.

    Will take in --range-config and --link-request arguments to generate 
    configs against.

    Note: if config is not empty, --override will need
    to be run to remove old configs

Steps:
    - Parse CLI args
    - Check for existing configs
        - remove if --override is set and configs exist
        - fail if --override is not set and configs exist
    - Load and Parse Range Config File
    - Generate configs for the plugin
    - Store configs in the specified config directory

usage:
    generate_configs.py \
        [-h] \
        --range RANGE_CONFIG_FILE \
        [--overwrite] \
        [--config-dir CONFIG_DIR] \
        [--network-manager-request NETWORK_MANAGER_REQUEST_FILE]

example call:
    ./generate_plugin_configs.py \
        --range=./2x2.json \
        --config-dir=./config \
        --overwrite
"""

# Python Library Imports
import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Local Lib Imports
RACE_UTILS_PATH = f"{os.path.dirname(os.path.realpath(__file__))}/../race-python-utils"
sys.path.insert(0, RACE_UTILS_PATH)
from race_python_utils import file_utils
from race_python_utils import range_config_utils
from race_python_utils import network_manager_request_utils
from race_python_utils import network_manager_utils
from race_python_utils import comms_link_utils


###
# Global
###

LOCAL = {
	'email_server': "racemail-raven.test",
	'password': "pass1234",
        'smtp_port': 587,
        'imap_port': 993,
        'insecure_tls': True,
}

CHANNEL_ID = "raven"
try:
    with open(
        f"{os.path.dirname(os.path.realpath(__file__))}/channel_properties.json"
    ) as json_file:
        CHANNEL_PROPERTIES = json.load(json_file)
except Exception as err:
    print(f"ERROR: Failed to read channel properties: {repr(err)}")
    CHANNEL_PROPERTIES = {}


###
# Main Execution
###


def main() -> None:
    """
    Purpose:
        Generate configs for twoSixIndirectGolang
    Args:
        N/A
    Returns:
        N/A
    Raises:
        Exception: Config Generation fails
    """
    logging.info("Starting Process To Generate RACE Configs")

    # Parsing Configs
    cli_args = get_cli_arguments()

    # Load and validate Range Config
    range_config = file_utils.read_json(cli_args.range_config_file)
    range_config_utils.validate_range_config(
        range_config=range_config, allow_no_clients=True
    )

    # Load (or create) and validate TA1 Request
    if cli_args.network_manager_request_file:
        network_manager_request = file_utils.read_json(cli_args.network_manager_request_file)
    else:
        network_manager_request = network_manager_request_utils.generate_network_manager_request_from_range_config(
            range_config, [CHANNEL_PROPERTIES], "unicast", "indirect"
        )
    network_manager_request_utils.validate_network_manager_request(network_manager_request, range_config)

    # Prepare the dir to store configs in, check for previous values and overwrite
    file_utils.prepare_comms_config_dir(cli_args.config_dir, cli_args.overwrite)

    # Generate Configs
    generate_configs(
        range_config,
        network_manager_request,
        cli_args.config_dir,
        cli_args.local_override,
        disable_s2s=cli_args.disable_s2s,
    )

    logging.info("Process To Generate RACE Plugin Config Complete")


###
# Generate Config Functions
###


def generate_configs(
    range_config: Dict[str, Any],
    network_manager_request: Dict[str, Any],
    config_dir: str,
    local_override: bool,
    disable_s2s: bool = False,
) -> None:
    """
    Purpose:
        Generate the plugin configs based on range config and network_manager request
    Args:
        range_config: range config to generate against
        network_manager_request: requested links to generate against
        config_dir: where to store configs
        local_override: Ignore range config services. Use Two Six Local Information.
    Raises:
        Exception: generation fails
    Returns:
        None
    """

    # Generate Genesis Link Addresses
    (link_addresses, fulfilled_network_manager_request) = generate_genesis_link_addresses(
        range_config,
        network_manager_request,
        local_override,
        disable_s2s=disable_s2s,
    )
    file_utils.write_json(
        {CHANNEL_ID: link_addresses},
        f"{config_dir}/genesis-link-addresses.json",
    )

    # Store the fufilled links to compare to the request (may need more iterations)
    file_utils.write_json(
        fulfilled_network_manager_request, f"{config_dir}/fulfilled-network-manager-request.json"
    )

    user_responses = generate_user_responses(range_config, local_override)
    file_utils.write_json(user_responses, f"{config_dir}/user-responses.json")
    
def init_vars(local_override):
    insecure_tls = LOCAL['insecure_tls']
    email_server = LOCAL['email_server']
    password = LOCAL['password']
    smtp_port = LOCAL['smtp_port']
    imap_port = LOCAL['imap_port']
    #if not local_override:
    	# TODO: Read in email server from range config
    	# TODO: Read in password from range config
    	# TODO
    	# TODO
        #raise(NotImplementedError)
    	# email_server = 
    	# password = 
    	# smtp_port =
    	# imap_port =
    return insecure_tls, email_server, password, smtp_port, imap_port


def generate_genesis_link_addresses(
    range_config: Dict[str, Any],
    network_manager_request: Dict[str, Any],
    local_override: bool,
    disable_s2s: bool = False,
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """
    Purpose:
        Generate indirect COMMS links utilizing Raven
    Args:
        range_config: range config to generate against
        network_manager_request: requested links to generate against
        local_override: Ignore range config services. Use Two Six Local Information.
    Raises:
        Exception: generation fails
    Returns:
        link_profiles: configs for the generated links
        fulfilled_network_manager_request: which network_manager links in the request were fufilled
    """

    link_addresses = {}

    link_profiles = []
    fulfilled_network_manager_request: Dict[str, Any] = {"links": []}

    # Build link properties
    (send_properties, receive_properties) = build_link_properties()
    
    insecure_tls, email_server, password, smtp_port, imap_port = init_vars(local_override)

    # Loop through requested links and create links
    for link_idx, requested_link in enumerate(network_manager_request["links"]):
        # Only create links for request for this channel
        if CHANNEL_ID not in requested_link["channels"]:
            continue
        requested_link["channels"] = [CHANNEL_ID]

        # Append link as fufilled, the links will be created
        fulfilled_network_manager_request["links"].append(requested_link)

        # Determine client/server hashtag. client if any clients involved
        if "client" in requested_link["sender"] or [
            recipient
            for recipient in requested_link["recipients"]
            if "client" in recipient
        ]:
        	pass
        # Skip all server to server links if disable_s2s is True
        elif disable_s2s:
            continue

        sender_node = requested_link["sender"]
        if sender_node not in link_addresses:
            link_addresses[sender_node] = []
        # This client to servers
        link_addresses[sender_node].append(
            {
                "role": "loader",
                "personas": requested_link["recipients"],
                "address": f'''{json.dumps({
                    "sender": requested_link["sender"] + "@" + email_server,
                    "rcvr": requested_link["recipients"][0] + "@" + email_server,
                })}''',
                "description": "link_type: send",
            }
        )

        for recipient in requested_link["recipients"]:
            if recipient not in link_addresses:
                link_addresses[recipient] = []
            # Servers to this client
            link_addresses[recipient].append(
                {
                    "role": "creator",
                    "personas": [sender_node],
                    "address": f'''{json.dumps({
                        "sender": requested_link["sender"] + "@" + email_server,
                        "rcvr": requested_link["recipients"][0] + "@" + email_server,
                    })}''',
                    "description": "link_type: receive",
                }
            )

    if len(fulfilled_network_manager_request["links"]) < len(network_manager_request["links"]):
        logging.warning(
            f"Not all links fufilled: {len(fulfilled_network_manager_request['links'])} of "
            f"{len(network_manager_request['links'])} fulfilled"
        )
    else:
        logging.info("All requested links fufilled")

    return (link_addresses, fulfilled_network_manager_request)


def build_link_properties() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Purpose:
        Build the link properties for the link.

        These are hard-code guesses for initial links
    Args:
        N/A
    Returns:
        send_properties: properties for send side users (best, expected, worst)
        receive_properties: properties for recieve side users (best, expected, worst)
    """

    # Build link properties
    link_bandwidth_bps = 308_000  # tested with rib local mode against v1.0.0
    link_latency_ms = 2_900  # tested with rib local mode against v1.0.0
    link_reliability = False
    link_transmission_type = "unicast"
    send_properties = comms_link_utils.generate_link_properties_dict(
        "send",
        link_transmission_type,
        link_reliability,
        link_latency_ms,
        link_bandwidth_bps,
        supported_hints=[],
    )
    receive_properties = comms_link_utils.generate_link_properties_dict(
        "receive",
        link_transmission_type,
        link_reliability,
        link_latency_ms,
        link_bandwidth_bps,
        supported_hints=[],
    )

    return (send_properties, receive_properties)


def generate_channel_settings() -> Dict[str, Any]:
    """Generate the global settings for the channel.

    Returns:
        Dict[str, Any]: The settings with string keys and values of various types. Intended to be written to file as json.
    """
    return {"settings": {"bogus": {"hostname": "ravenfoo", "port": 5000}}}
    

def generate_user_responses(
    range_config: Dict[str, Any], local_override: bool
) -> Dict[str, Dict[str, str]]:
    """
    Purpose:
        Generate the user input responses based on the range config
    Args:
        range_config: range config to generate against
    Return:
        Mapping of node persona to mapping of prompt to response
    """
    responses = {}
    
    insecure_tls, email_server, password, smtp_port, imap_port = init_vars(local_override)
    
    range_config_clients = range_config_utils.get_client_details_from_range_config(
        range_config
    )
    for persona in range_config_clients.keys():
        responses[persona] = {
            "emailProfile": json.dumps({
                        "hostname": email_server,
                        "address": persona + "@" + email_server,
                        "password": password,
                        "smtp_port": smtp_port,
                        "imap_port": imap_port,
                        "insecure_TLS": insecure_tls,
                    }),
        }

    range_config_servers = range_config_utils.get_server_details_from_range_config(
        range_config
    )
    for persona in range_config_servers.keys():
        responses[persona] = {
            "emailProfile": json.dumps({
                        "hostname": email_server,
                        "address": persona + "@" + email_server,
                        "password": password,
                        "smtp_port": smtp_port,
                        "imap_port": imap_port,
                        "insecure_TLS": insecure_tls,
                    }),
        }
    
    return responses


###
# Helper Functions
###


def get_cli_arguments() -> argparse.Namespace:
    """
    Purpose:
        Parse CLI arguments for script
    Args:
        N/A
    Return:
        cli_arguments (ArgumentParser Obj): Parsed Arguments Object
    """
    logging.info("Getting and Parsing CLI Arguments")

    parser = argparse.ArgumentParser(description="Generate RACE Config Files")
    required = parser.add_argument_group("Required Arguments")
    optional = parser.add_argument_group("Optional Arguments")

    # Required Arguments
    required.add_argument(
        "--range",
        dest="range_config_file",
        help="Range config of the physical network",
        required=True,
        type=str,
    )

    # Optional Arguments
    optional.add_argument(
        "--overwrite",
        dest="overwrite",
        help="Overwrite configs if they exist",
        required=False,
        default=False,
        action="store_true",
    )
    optional.add_argument(
        "--local",
        dest="local_override",
        help=(
            "Ignore range config service connectivity, utilize "
            "local configs (e.g. local hostname/port vs range services fields)"
        ),
        required=False,
        default=False,
        action="store_true",
    )
    optional.add_argument(
        "--disable-s2s",
        dest="disable_s2s",
        help="Disable Server to Server Links for Indirect Channel",
        required=False,
        default=False,
        action="store_true",
    )
    optional.add_argument(
        "--config-dir",
        dest="config_dir",
        help="Where should configs be stored",
        required=False,
        default="./configs",
        type=str,
    )
    optional.add_argument(
        "--network-manager-request",
        dest="network_manager_request_file",
        help=(
            "Requested links from NETWORK MANAGER. Configs should generate only these"
            " links and as many of the links as possible. RiB local will not have the "
            "same network connectivty as the T&E range."
        ),
        required=False,
        default=False,
        type=str,
    )

    return parser.parse_args()


###
# Entrypoint
###


if __name__ == "__main__":

    LOG_LEVEL = logging.INFO
    logging.getLogger().setLevel(LOG_LEVEL)
    logging.basicConfig(
        stream=sys.stdout,
        level=LOG_LEVEL,
        format="[generate_comms_golang_indirect_configs] %(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%a, %d %b %Y %H:%M:%S",
    )

    try:
        main()
    except Exception as err:
        print(f"{os.path.basename(__file__)} failed due to error: {err}")
        raise err