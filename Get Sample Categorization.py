"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
import networksage_common_resources as resources
import json
import requests

# Constants:
VALID_ENTITY_TYPES = ["DOMAIN", "ADDRESS", "GENERICENTITY", "DestinationURL", EntityTypes.DESTINATIONDOMAIN,
                      EntityTypes.ADDRESS, EntityTypes.GENERIC, EntityTypes.URL, EntityTypes.HOSTNAME
                      ]

siemplify = SiemplifyAction()  # global instance


@output_handler
def main():
    api_key = siemplify.extract_configuration_param(resources.INTEGRATION_NAME, "apikey")
    sample_id = siemplify.extract_action_param(param_name="private_sample_id", print_value=True)
    sample_info = json.loads(sample_id)
    sample_id = sample_info["sampleId"].lower()
    siemplify.LOGGER.info(f"Got private_sample_id value of {sample_id}")
    url = f"https://api.seclarity.io/sec/v1.0/samples/{sample_id}/categorization"
    status = EXECUTION_STATE_FAILED  # default to fail case
    payload = {}
    headers = {'apikey': api_key}
    response = requests.request("GET", url, headers=headers, data=payload)  # try to get it if it already exists
    result_value = None  # Set a simple result value, used for playbook if\else and placeholders.
    ui_message = f"failed to get sample categorization"  # human-readable message, shown in UI as the action result

    if response.status_code != requests.codes.ok:
        siemplify.LOGGER.error("Error attempting to retrieve sample: {}".format(response.text))
    else:
        result = response.json()
        if result["error"]:
            siemplify.LOGGER.error("Error retrieving sample: {}".format(result["body"]))
        elif result["body"]["status"] == "failed":
            siemplify.LOGGER.info("No categorization existed. Requesting a new one.")
            response = requests.request("POST", url, headers=headers, data=payload)  # try to generate it.
            if response.status_code != requests.codes.ok:
                siemplify.LOGGER.error("Error attempting to generate sample: {}".format(response.text))
            else:
                result = resources.wait_for_sample_action(siemplify,
                                                          url,
                                                          headers,
                                                          action="categorization"
                                                          )  # polling at defined interval
                if result is None:
                    siemplify.LOGGER.error("Error retrieving data for sample.")
                else:
                    status, ui_message, result_value = resources.finish_storing_result(siemplify,
                                                                                       result,
                                                                                       "SampleCategorization"
                                                                                       )
        else:
            result = result["body"]["categorization"]  # have to pass the actual categorization data
            status, ui_message, result_value = resources.finish_storing_result(siemplify,
                                                                               result,
                                                                               "SampleCategorization"
                                                                               )
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  ui_message: {}".format(status,
                                                                                        result_value,
                                                                                        ui_message
                                                                                        )
                          )
    siemplify.end(ui_message, result_value, status)


if __name__ == "__main__":
    main()
