"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
# =====================================
#             IMPORTS                 #
# =====================================
import requests
import threading
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT


# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = "NetworkSage"
WAIT_TIME = 15.0
NETWORKSAGE_INTERESTING_CATEGORIES_REGEX = r"(Attack Vector|Suspicious|Malicious|Impact)"


# =====================================
#             UTILITIES               #
# =====================================

def wait_for_sample_action(siemplify, url, headers, action="summary"):
    """Wrapper to poll until sample has been summarized or categorized. When this returns, the sample summary or
       categorization will be ready.
    """
    data = None
    action_checking_timer = threading.Event()
    gap_for_processing = 120  # seconds to wait in case sample hasn't yet been processed; when it is we can get its info
    while not action_checking_timer.wait(WAIT_TIME):  # check every 15 seconds
        response = requests.request("GET", url, headers=headers, data={})
        try:
            result = response.json()
            if result["body"]["status"] == "generated":
                action_checking_timer.set()
                data = result["body"][action]
                break
            elif result["body"]["status"] == "failed":
                if gap_for_processing > 0:
                    gap_for_processing -= WAIT_TIME
                    siemplify.LOGGER.info("Status shows failed, but wait time (in case sample hasn't yet been "
                                          "processed) is still {} seconds. Waiting a little longer.".format(
                        gap_for_processing))
                else:
                    break  # it for real failed
        except:
            siemplify.LOGGER.error("Something went wrong while getting sample {}: {}".format(action, response.text))
    return data


def finish_storing_result(siemplify, result, result_type):
    """Saves the result JSON for use by other steps.
    """
    try:
        siemplify.result.add_result_json(result) # this is the only success case
        siemplify.result.add_json(result_type, result)
        ui_message = f"successfully got {result_type} for sample"
        status = EXECUTION_STATE_COMPLETED  # used to flag back to siemplify system, the action final status
        result_value = result
    except Exception as e:
        siemplify.LOGGER.error("Something went wrong while trying to access data: {}".format(result["body"]))
        status = EXECUTION_STATE_FAILED
        ui_message = f"failed to get {result_type} for sample"
        result_value = None
    return status, ui_message, result_value
