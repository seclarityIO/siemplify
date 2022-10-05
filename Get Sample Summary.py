"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io), structure based on Siemplify example code.
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
import networksage_common_resources as resources
import ipaddress
import json
import requests
import re

# Constants:
VALID_ENTITY_TYPES = ["DOMAIN", "ADDRESS", "GENERICENTITY", "DestinationURL", EntityTypes.DESTINATIONDOMAIN,
                      EntityTypes.ADDRESS, EntityTypes.GENERIC, EntityTypes.URL, EntityTypes.HOSTNAME
                      ]

siemplify = SiemplifyAction()  # global instance


def add_summary_as_general_insight(result_json):
    """Add a General Case Insight with the high-level info about what we believe for the sample. This also turns our
       mrkdwn (Slack) formatting into roughly equivalent HTML formatting.
    """
    try:
        result_json['summary'] = re.sub(r"[^`]`([a-zA-Z \-]+)`\)[^`]", r" <b><i>\1</i></b>) ", result_json['summary'])
        result_json['summary'] = re.sub(r"[^`]`([a-zA-Z \-]+)`[^`]", r" <b><i>\1</i></b> ", result_json['summary'])
        result_json['summary'] = re.sub(r"_([a-zA-Z]+)_", r"<i>\1</i>", result_json['summary'])
        result_json['summary'] = re.sub(r"\*([a-zA-Z ]+)\*", r"<b>\1</b>", result_json['summary'])
        result_json['summary'] = re.sub(r"please review the <b><i>Details</i></b> section below.",
                                        r"please review the entities and insights added to this case.",
                                        result_json["summary"]
                                        )
    except Exception as e:
        siemplify.LOGGER.info(f"Attempt to reformat sample summary as HTML failed: {e}")
    try:
        general_insight_content = f"<b>Verdict:</b> {result_json['verdict']}\n <b>Confidence:</b> " \
                                  f"{result_json['confidence']}\n <b>Summary:</b> {result_json['summary']}"
        siemplify.create_case_insight(resources.INTEGRATION_NAME,
                                      f"Sample Summary by {resources.INTEGRATION_NAME}",
                                      general_insight_content,
                                      "",
                                      0,
                                      0
                                      )
    except Exception as e:
        siemplify.LOGGER.warn(f"Failed to generate insight for Sample Summary: {e}")


def collect_destination_info_from_details(details_raw_content):
    """Do some parsing of our "details" content to collect the destination name, confidence, and
       description by category.
    """
    siemplify.LOGGER.info(f"Looking for destinations in {details_raw_content}")
    categories_raw = re.findall(r"We have observed [1-9]{1}[0-9]{0,} [a-zA-Z]* ?[A-Z][a-z]+", details_raw_content)
    known_attack_vectors_raw = re.findall(r"There [a-z]+ [0-9]+ known Attack Vectors", details_raw_content)
    suspected_attack_vectors_raw = re.findall(r"there [a-z]+ [0-9]+ which we suspect could be Attack Vectors",
                                              details_raw_content
                                              )
    uninteresting_page_loads_raw = re.findall(r"There [a-z]+ [0-9]+ page[s ] loading in this sample",
                                              details_raw_content
                                              )
    siemplify.LOGGER.info(f"known attack vectors: {known_attack_vectors_raw}")
    siemplify.LOGGER.info(f"suspected attack vectors: {suspected_attack_vectors_raw}")
    siemplify.LOGGER.info(f"uninteresting page loads: {uninteresting_page_loads_raw}")
    categories_raw = known_attack_vectors_raw + suspected_attack_vectors_raw + categories_raw
    siemplify.LOGGER.info(f"raw categories: {categories_raw}")
    destinations_raw = re.findall(r"(\. `|\*Destination Name:\* )(.*\.[a-zA-Z0-9]+:)", details_raw_content)
    siemplify.LOGGER.info(f"raw destinations: {destinations_raw}")
    confidence_raw = re.findall(r"\*Confidence:\* [a-zA-z]{1,}", details_raw_content)
    description_raw = re.findall(r"\*Description:\* ```(?s:.*?)```", details_raw_content)
    interesting_destinations = []
    confidences = []
    descriptions = []
    destination_details = dict()
    for d in destinations_raw:  # collect just the name.tld or IP
        try:
            destination_name = d[1]  # each entry is a tuple
        except:
            destination_name = d
        try:
            interesting_destinations += [destination_name[:-1]]
        except Exception as e:
            interesting_destinations += ["unknown_destination"]
            siemplify.LOGGER.warn(f"Something went wrong while trying to collect destination name: {e}")
    for conf in confidence_raw:
        try:
            confidences += [conf[conf.rfind(" "):]]
        except Exception as e:
            siemplify.LOGGER.warn(f"Something went wrong while trying to collect confidence: {e}")
            confidences += ["unknown_confidence"]
    for description in description_raw:
        try:
            descriptions += [description[18:-4]]
        except Exception as e:
            siemplify.LOGGER.warn(f"Something went wrong while trying to collect description: {e}")
            descriptions += ["unknown_description"]
    zipped_destinations_info = list(zip(interesting_destinations, confidences, descriptions))
    siemplify.LOGGER.info(f"Destination info collected from summary: {zipped_destinations_info}")
    accounted_for = 0
    for c in categories_raw:
        match = re.search(resources.NETWORKSAGE_INTERESTING_CATEGORIES_REGEX, c)
        if match is not None:
            cc = re.search(r"[0-9]+", c)
            if cc is not None:
                try:
                    category_count = int(cc.group(0))
                except:
                    siemplify.LOGGER.warn(f"Expected to find a number in {c}, but failed to do so.")
                    category_count = [0]
            else:
                category_count = 0
            category_name = match.group(0)
            siemplify.LOGGER.info(f"Found category {category_name}")
        else:
            category_name = "unknown"
            category_count = 0
            siemplify.LOGGER.warn(f"Expected to find a valid category in {c}, but failed to do so.")
        if category_name not in destination_details:
            destination_details[category_name] = []
        for i in range(0 + accounted_for, category_count + accounted_for):
            destination_details[category_name] += [zipped_destinations_info[i]]
            accounted_for += 1
    return destination_details


def update_or_add_certain_entity_types(summary_details):
    """For entities that we believe to be Suspicious, Malicious, Impact, or Attack Vectors (based on our summary
       details), update (or add if they don't exist) their info with our summary knowledge. Also add an Entity Insight.
       ###TODO: Why won't adding an Entity Insight work in the same pass as adding the Entity?
    """
    successful_updated_entities = []
    successful_added_entities = dict()
    details_raw_content = summary_details
    destination_details = collect_destination_info_from_details(details_raw_content)
    siemplify.LOGGER.info(f"All raw destination details: {destination_details}")
    potential_entities_to_update = dict()
    siemplify.LOGGER.info(f"Collecting entities that we may update.")
    current_alert_id = None
    for entity in siemplify.target_entities:
        if entity.entity_type in VALID_ENTITY_TYPES:
            potential_entities_to_update[entity.identifier] = entity
            current_alert_id = entity.alert_identifier
        else:
            siemplify.LOGGER.info(f"Didn't process {entity.entity_type} {entity.identifier}")
    for category in destination_details:
        siemplify.LOGGER.info(f"Reviewing destinations categorized as {category}")
        for destination_data in destination_details[category]:
            name = destination_data[0]
            confidence = destination_data[1]
            description = destination_data[2]
            siemplify.LOGGER.info(f"Checking to see if {name} is in {potential_entities_to_update}")
            if name in potential_entities_to_update:  # it already exists, so just update it
                siemplify.LOGGER.info(f"{name} exists, so updating it!")
                entity_data = potential_entities_to_update[name]
                entity_data.additional_properties.update({"NetworkSage Categorization": category,
                                                          "NetworkSage Confidence": confidence,
                                                          "NetworkSage Reason": description
                                                          })
                successful_updated_entities += [entity_data]
                try:
                    siemplify.add_entity_insight(domain_entity_info=entity_data,
                                                 message=f"This destination seems to be {category} in this sample. "
                                                         f"{description}"
                                                 )
                except Exception as e:
                    siemplify.LOGGER.warn(f"Failed to add insight for entity {name}: {e}")
            else:
                siemplify.LOGGER.info(f"Couldn't find {name}, so creating it and updating its info")
                if current_alert_id is None:
                    for a in siemplify.case.alerts:
                        current_alert_id = a.identifier
                else:
                    siemplify.LOGGER.info(f"Going to attach this new entity to the last alert we processed that had "
                                          f"relevant data")
                siemplify.LOGGER.info(f"Adding {name} as an entity to alert ID {current_alert_id}")
                try:
                    ipaddress.ip_address(name)
                    etype = "ADDRESS"
                except:
                    etype = "DOMAIN"
                try:
                    res = siemplify.add_entity_to_case(case_id=siemplify.case.identifier,
                                                       alert_identifier=current_alert_id,
                                                       entity_identifier=name,
                                                       entity_type=etype,
                                                       is_internal=True,
                                                       is_suspicous=True if category != "Attack Vector" else False,
                                                       is_enriched=True,
                                                       is_vulnerable=False,
                                                       properties={"NetworkSage Categorization": category,
                                                                   "NetworkSage Confidence": confidence,
                                                                   "NetworkSage Reason": description
                                                                   },
                                                       environment=None
                                                       )
                    siemplify.LOGGER.info(f"Successfully added {name} to case!")
                    siemplify.LOGGER.info(f"Result value of adding entity is {res}")
                    successful_added_entities[name] = {"category": category,
                                                       "description": description
                                                       }
                except Exception as e:
                    siemplify.LOGGER.warn(f"Failed to add {name} to case: {e}")
    return successful_updated_entities, successful_added_entities


def update_and_add_entity_insights(new_entities):
    """Note, this is currently a no-op, as it seems impossible to actually get a newly-added Entity's
       information within the same Action call that added it.
    """
    entities_to_update = []
    siemplify.LOGGER.info(f"ATTEMPTING TO UPDATE CASE with {new_entities.keys()}")
    try:
        # call with an empty list to make sure things have been pushed to the case
        siemplify.update_entities(updated_entities=new_entities.keys())
    except Exception as e:
        siemplify.LOGGER.info(f"Failed to add new entities in a way that we can reference them, despite API docs "
                              f"saying it's possible.")
        return entities_to_update
    siemplify.LOGGER.info(f"After update, new full Entities list is {siemplify.target_entities}")
    for target in siemplify.target_entities:
        siemplify.LOGGER.info(f"Checking to see if {target.identifier} matches any entities")
        if target.identifier in new_entities:
            try:
                siemplify.add_entity_insight(domain_entity_info=target,
                                             message=f"This destination seems to be "
                                                     f"{new_entities[target.identifier]['category']} in this sample. "
                                                     f"{new_entities[target.identifier]['description']}"
                                             )
                entities_to_update += [target]  # this should allow Entity insight in one pass
            except Exception as e:
                siemplify.LOGGER.warn(f"Failed to add insight for entity {target.identifier}: {e}")
    return entities_to_update


@output_handler
def main():
    api_key = siemplify.extract_configuration_param(resources.INTEGRATION_NAME, "apikey")
    sample_id = siemplify.extract_action_param(param_name="private_sample_id", print_value=True)
    sample_info = json.loads(sample_id)
    sample_id = sample_info["sampleId"].lower()
    siemplify.LOGGER.info(f"Got private_sample_id value of {sample_id}")
    url = f"https://api.seclarity.io/sec/v1.0/samples/{sample_id}/summary"
    status = EXECUTION_STATE_FAILED  # default to fail case
    payload = {}
    headers = {'apikey': api_key}
    response = requests.request("GET", url, headers=headers, data=payload)  # try to get it if it already exists

    result_value = None  # Set a simple result value, used for playbook if\else and placeholders.
    ui_message = f"failed to get sample summary"  # human-readable message, shown in UI as the action result
    if response.status_code != requests.codes.ok:
        siemplify.LOGGER.error("Error attempting to retrieve sample: {}".format(response.text))
        result = None
    else:
        result = response.json()
        if result["error"]:
            siemplify.LOGGER.error("Error retrieving sample: {}".format(result["body"]))
        elif result["body"]["status"] == "failed":
            siemplify.LOGGER.info("No summary existed. Requesting a new one.")
            response = requests.request("POST", url, headers=headers, data=payload)  # try to generate it
            if response.status_code != requests.codes.ok:
                siemplify.LOGGER.error("Error attempting to generate sample: {}".format(response.text))
            else:
                result = resources.wait_for_sample_action(siemplify,
                                                          url,
                                                          headers,
                                                          action="summary"
                                                          )  # polling at defined interval
                if result is None:
                    siemplify.LOGGER.error("Error retrieving data for sample.")
                else:
                    status, ui_message, result_value = resources.finish_storing_result(siemplify,
                                                                                       result,
                                                                                       "SampleSummary"
                                                                                       )
        else:
            result = result["body"]["summary"]  # have to pass the actual summary data
            status, ui_message, result_value = resources.finish_storing_result(siemplify,
                                                                               result,
                                                                               "SampleSummary"
                                                                               )
    if result is not None:
        result_json = json.loads(result)
    else:
        result_json = {}
    add_summary_as_general_insight(result_json)
    successful_updated_entities, successful_added_entities = update_or_add_certain_entity_types(result_json["details"])
    if successful_updated_entities:
        ui_message += "\n Successfully updated entities:\n   {}".format(
            "\n   ".join([x.identifier for x in successful_updated_entities]))
        siemplify.update_entities(successful_updated_entities)
    else:
        ui_message += "\n No entities were updated."
    if successful_added_entities:
        final_new_entries = update_and_add_entity_insights(successful_added_entities)
        if len(final_new_entries) > 0:
            ui_message += "\n Successfully added entities with insights:\n {}".format(
                "\n   ".join([x.identifier for x in final_new_entries]))
            siemplify.update_entities(final_new_entries)
        else:
            ui_message += "\n Successfully added entities (without insights):\n {}".format(
                "\n   ".join([x for x in successful_added_entities.keys()]))
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  ui_message: {}".format(
        status, result_value, ui_message))
    siemplify.end(ui_message, result_value, status)


if __name__ == "__main__":
    main()
