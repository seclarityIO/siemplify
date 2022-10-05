"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
import networksage_common_resources as resources
import requests


@output_handler
def main():
    siemplify = SiemplifyAction()

    api_key = siemplify.extract_configuration_param(resources.INTEGRATION_NAME, "apikey")
    default_destination = siemplify.extract_action_param(param_name="destination", print_value=True)

    url = f"https://api.seclarity.io/sec/v1.0/destinations/{default_destination}"
    ui_message = "Successful connection!"

    headers = {'apikey': api_key}
    response = requests.request("GET", url, headers=headers, data={})

    if response.status_code != requests.codes.ok:
        siemplify.LOGGER.error("Error retrieving destination: {}".format(response.text))
        ui_message = "Failed connection"
    else:
        result = response.json()
        if result["error"]:
            siemplify.LOGGER.error("Error retrieving destination: {}".format(result["body"]))
            ui_message = "Failed connection"
        else:
            siemplify.LOGGER.info("Destination details fetched: {}".format(result["body"]))
    siemplify.end(ui_message, True)


if __name__ == "__main__":
    main()
