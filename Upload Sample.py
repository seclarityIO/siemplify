"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io), structure based on Siemplify example code.
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
import networksage_common_resources as resources
import datetime
import json
import requests
import pathlib

siemplify = SiemplifyAction() # global instance


@output_handler
def main():
    api_key = siemplify.extract_configuration_param(resources.INTEGRATION_NAME, "apikey")
    url = "https://api.seclarity.io/upload/v1.0/uploader"
    sample_type = siemplify.extract_action_param(param_name="sample_type", print_value=True).lower()
    sample_json_data = siemplify.extract_action_param(param_name="sample_json_data",
                                                      is_mandatory=False,
                                                      print_value=True)
    sample_binary_data = siemplify.extract_action_param(param_name="sample_binary_data",
                                                        is_mandatory=False,
                                                        print_value=True)
    zeek_dnslog_json_data = siemplify.extract_action_param(param_name="zeek_dnslog_json_data",
                                                           is_mandatory=False,
                                                           print_value=True)
    dnslog_path = None
    sample_path = None
    result_value = None  # Set a simple result value, used for playbook if\else and placeholders.
    response = None

    time_prefix = datetime.datetime.now().strftime("%m-%d-%y_T_%H-%M-%S.%f")
    # we need things in a binary stream for our processing, so store temporarily
    temporary_sample_location = pathlib.Path(f"/tmp/{resources.INTEGRATION_NAME}_{time_prefix}.json")
    temporary_dnslog_location = pathlib.Path(f"/tmp/{resources.INTEGRATION_NAME}_{time_prefix}_dns.json")
    sample_file_path = None
    ui_message = f"failed to upload {sample_type} sample"  # human-readable message, shown in UI as the action result

    if sample_json_data is not None:  # if we somehow got null values in, we should stringify them.
        sample_json_data.replace(": null", ": \"null\"")

    if sample_json_data is None and sample_binary_data is None:
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error("\n Error: no data passed in for sample.")
    elif sample_binary_data is None and sample_type.lower() in ["pcap", "pcapng"]:
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(f"\n Error: Missing binary data for {sample_type} sample.")
    else:
        # FOR TESTING CASE ONLY!
        if sample_json_data is None and sample_binary_data is not None and sample_binary_data == "thisisadefaultvalue":
            test_data = requests.get("https://github.com/seclarityIO/public-tools/blob/main/src/networksage_tools/converter/tests/inputs/testCase4_onePacketIsProcessable.pcapng?raw=true")
            siemplify.LOGGER.info("Performing a test with a public PCAP file.")
            sample_file_path = "/tmp/testing"
            with open(sample_file_path, "wb") as test_out:
                test_out.write(test_data.content)
            sample_type = "pcap"
        if sample_type.lower() in ["interflow", "zeek"] and sample_json_data is not None:
            siemplify.LOGGER.info(f"Sample data: {sample_json_data}")
            try:
                sample_json_data = json.loads(sample_json_data)  # it comes in as a string, so convert it.
            except Exception as e:
                siemplify.LOGGER.warn(f"Could not convert sample_json_data into JSON: {e}")
                status = EXECUTION_STATE_FAILED
            siemplify.LOGGER.info(f"Sample data type: {type(sample_json_data)}")
            with open(temporary_sample_location, "w") as out:
                json.dump(sample_json_data, out)
                sample_file_path = temporary_sample_location
        if sample_type.lower() == "zeek" and zeek_dnslog_json_data is not None and len(zeek_dnslog_json_data) > 0:
            # try to open dns log's file path
            try:
                sample_dns_data = json.loads(zeek_dnslog_json_data)
            except Exception as e:
                status = EXECUTION_STATE_FAILED
                siemplify.LOGGER.error("\n Error occurred while trying to load zeek_dnslog_json_data: {}\n".format(e))
            with open(temporary_dnslog_location, "w") as out:
                json.dump(sample_dns_data, out)
                dnslog_path = temporary_dnslog_location
        try:
            sample_path = pathlib.Path(sample_file_path)
        except Exception as e:
            status = EXECUTION_STATE_FAILED
            siemplify.LOGGER.error("\n Error occurred while trying to open sample_file_path: {}\n".format(e))
        if sample_path is not None:
            # try to upload sample to NetworkSage
            try:
                payload = {'type': sample_type}
                files = [
                    ('file', (sample_path.name, open(sample_path, 'rb'), 'application/octet-stream'))
                ]
                if dnslog_path is not None:  # add DNS log info when it exists
                    files += [
                        ('zeekDnsFile',
                         (f"dns_{dnslog_path.name}",
                          open(dnslog_path, 'rb'),
                          'application/octet-stream'
                          )
                         )
                    ]
                headers = {'apikey': api_key}
                response = requests.request("POST", url, headers=headers, data=payload, files=files)
            except Exception as e:
                status = EXECUTION_STATE_FAILED
                siemplify.LOGGER.error("\n Error occurred while trying to prepare upload: {}\n".format(e))
        else:
            siemplify.LOGGER.error("Error: No sample path found.")
            status = EXECUTION_STATE_FAILED
        if response is None:
            siemplify.LOGGER.error("Something failed while attempting to uploading sample")
        elif response.status_code != requests.codes.ok:
            siemplify.LOGGER.error("Error uploading sample: {}".format(response.text))
        else:
            result = response.json()
            if result["error"]:
                siemplify.LOGGER.error("Error uploading sample: {}".format(result["body"]))
            else:
                try:
                    siemplify.result.add_result_json(result["body"]) # this is the only success case
                    siemplify.result.add_json("SampleUploadDetails", result["body"])
                    ui_message = f"successfully uploaded {sample_type} sample"
                    status = EXECUTION_STATE_COMPLETED  # used to flag back to siemplify system, the action final status
                except Exception as e:
                    siemplify.LOGGER.error("Something went wrong while trying to access sample ID: {}"
                                           "".format(result["body"]))
                    status = EXECUTION_STATE_FAILED
    if result_value is not None:
        result_value = result["body"]
    if temporary_sample_location.exists():
        siemplify.LOGGER.info(f"Removing temporary sample at {temporary_sample_location}")
        temporary_sample_location.unlink()
    if temporary_dnslog_location.exists():
        siemplify.LOGGER.info(f"Removing temporary DNS data at {temporary_dnslog_location}")
        temporary_dnslog_location.unlink()
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  ui_message: {}".format(status, result_value, ui_message))
    siemplify.end(ui_message, result_value, status)


if __name__ == "__main__":
    main()
