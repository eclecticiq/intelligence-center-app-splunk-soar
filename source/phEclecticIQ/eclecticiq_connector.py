#!/usr/bin/python
# -*- coding: utf-8 -*-
# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
import urllib
import re

import logging
import datetime
import time

import math
import decimal
import eiq_api as eiqlib


class EclecticiqAppConnector(BaseConnector):

    def __init__(self):

        super(EclecticiqAppConnector, self).__init__()
        self._state = None
        self._headers = None
        self._base_url = None

    def _handle_on_poll(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_of_id == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Outgoing Feed ID in asset parameters"), None)

        artifact_count = param.get("artifact_count", 0)
        container_count = param.get("container_count", 0)

        feed_info = self.eiq_api.get_feed_info(str(self._tip_of_id))

        if feed_info[0]['update_strategy'] not in ['REPLACE', 'APPEND']:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Outgoing feed update strategy not supported."), None)
        elif feed_info[0]['packaging_status'] != 'SUCCESS':
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Outgoing feed is running now. Wait for run"
                                                                      " complete first."), None)

        if feed_info[0]['update_strategy'] == 'REPLACE':
            feed_content_block_list = self.eiq_api.get_feed_content_blocks(feed=feed_info[0])
            containers_processed = 0
            artifacts_processed = 0

            for idx, record in enumerate(feed_content_block_list):
                if containers_processed >= container_count != 0:
                    self.send_progress("Reached container polling limit: {0}".format(containers_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                if artifacts_processed >= artifact_count != 0:
                    self.send_progress("Reached artifacts polling limit: {0}".format(artifacts_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                self.send_progress("Processing block # {0}".format(idx))
                downloaded_block = json.loads(self.eiq_api.download_block_list(record))

                events = downloaded_block.get('entities', [])
                results = []

                for i in events:
                    idref = i['meta'].get('is_unresolved_idref', False)

                    if i['data']['type'] != "relation" and idref is not True:
                        container = {}
                        container['data'] = i
                        container['source_data_identifier'] = "EIQ Platform, OF: {0}, id#{1}. Entity id:{2}"\
                            .format(feed_info[0]["name"], feed_info[0]["id"], i['id'])

                        container['name'] = i['data'].get('title', 'No Title') + " - type: "\
                                            + i['data'].get('type', 'No Type')

                        container['id'] = i['id']

                        if i['meta'].get('tlp_color', "") in ["RED", "AMBER", "GREEN", "WHITE"]:
                            container['sensitivity'] = i['meta'].get('tlp_color', "").lower()

                        try:
                            severity = i['data']['impact']['value']
                            if severity in ["High", "Medium", "Low"]:
                                container['severity'] = severity.lower()
                        except KeyError:
                            pass

                        container['tags'] = i["meta"]["tags"]

                        if len(i["meta"].get("taxonomy_paths", "")) > 0:
                            for ii in i["meta"]["taxonomy_paths"]:
                                container['tags'].append(ii[-1])

                        artifacts = self._create_artifacts_for_event(i)
                        results.append({'container': container, 'artifacts': artifacts})

                containers_processed, artifacts_processed = \
                    self._save_results(results, containers_processed, artifacts_processed, artifact_count, container_count)

        elif feed_info[0]['update_strategy'] == 'APPEND':
            feed_last_run = {}
            feed_last_run['last_ingested'] = self._state.get('last_ingested', None)
            feed_last_run['created_at'] = self._state.get('created_at', None)

            feed_content_block_list = self.eiq_api.get_feed_content_blocks(feed=feed_info[0], feed_last_run=feed_last_run)
            containers_processed = 0
            artifacts_processed = 0

            for idx, record in enumerate(feed_content_block_list):
                if containers_processed >= container_count != 0:
                    self._state['last_ingested'] = str(record)
                    self._state['created_at'] = feed_info[0]['created_at']
                    self.save_state(self._state)

                    self.send_progress("Reached container polling limit: {0}".format(containers_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                if artifacts_processed >= artifact_count != 0:
                    self._state['last_ingested'] = str(record)
                    self._state['created_at'] = feed_info[0]['created_at']
                    self.save_state(self._state)

                    self.send_progress("Reached artifacts polling limit: {0}".format(artifacts_processed))
                    return self.set_status(phantom.APP_SUCCESS)

                self.send_progress("Processing block # {0}".format(idx))
                downloaded_block = json.loads(self.eiq_api.download_block_list(record))

                events = downloaded_block.get('entities', [])
                results = []

                for i in events:
                    idref = i['meta'].get('is_unresolved_idref', False)

                    if i['data']['type'] != "relation" and idref is not True:
                        container = {}
                        container['data'] = i
                        container['source_data_identifier'] = "EIQ Platform, OF: {0}, id#{1}. Entity id:{2}"\
                            .format(feed_info[0]["name"], feed_info[0]["id"], i['id'])

                        container['name'] = i['data'].get('title', 'No Title') + " - type: "\
                                            + i['data'].get('type', 'No Type')

                        container['id'] = i['id']

                        if i['meta'].get('tlp_color', "") in ["RED", "AMBER", "GREEN", "WHITE"]:
                            container['sensitivity'] = i['meta'].get('tlp_color', "").lower()

                        try:
                            severity = i['data']['impact']['value']
                            if severity in ["High", "Medium", "Low"]:
                                container['severity'] = severity.lower()
                        except KeyError:
                            pass

                        container['tags'] = i["meta"]["tags"]

                        if len(i["meta"].get("taxonomy_paths", "")) > 0:
                            for ii in i["meta"]["taxonomy_paths"]:
                                container['tags'].append(ii[-1])

                        artifacts = self._create_artifacts_for_event(i)
                        results.append({'container': container, 'artifacts': artifacts})

                containers_processed, artifacts_processed = \
                    self._save_results(results, containers_processed, artifacts_processed, artifact_count, container_count)

                self._state['last_ingested'] = str(record)
                self._state['created_at'] = feed_info[0]['created_at']
                self.save_state(self._state)

        return self.set_status(phantom.APP_SUCCESS)

    def _save_results(self, results, containers_processed, artifacts_processed, artifacts_limit, containers_limit):
        for idx, item in enumerate(results):
            self.send_progress("Adding Container # {0}".format(idx))

            if containers_processed < containers_limit or containers_limit == 0:
                ret_val, response, container_id = self.save_container(item['container'])
                self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, response, container_id))
                containers_processed += 1
                if phantom.is_fail(ret_val):
                    continue
            else:
                return containers_processed, artifacts_processed

            artifacts = item['artifacts']
            len_artifacts = len(artifacts)

            for idx2, artifact in enumerate(artifacts):
                if artifacts_processed < artifacts_limit or artifacts_limit == 0:
                    if (idx2 + 1) == len_artifacts:
                        # mark it such that active playbooks get executed
                        artifact['run_automation'] = True

                    artifact['container_id'] = container_id
                    self.send_progress("Adding Container # {0}, Artifact # {1}".format(idx, idx2))
                    ret_val, status_string, artifact_id = self.save_artifact(artifact)
                    artifacts_processed += 1
                    self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))
                else:
                    return containers_processed, artifacts_processed

        return containers_processed, artifacts_processed

    def _create_artifacts_for_event(self, event):
        artifacts = []
        observables = event.get('extracts')

        if not observables:
            return artifacts

        for i in observables:
            artifact = dict()

            artifact['data'] = i
            artifact['source_data_identifier'] = i['value']
            artifact['name'] = (i['kind']).capitalize() + " Artifact"
            artifact['cef'] = cef = dict()
            cef['observationId'] = i['value']
            cef['msg'] = "EclecticIQ Threat Intelligence observable"

            if i['meta'].get('classification', ""):
                cef['cs2'] = i['meta']['classification']
                cef['cs2Label'] = "EclecticIQClassification"

            if i['meta'].get('confidence', ""):
                cef['cs3'] = i['meta']['confidence']
                cef['cs3Label'] = "EclecticIQConfidence"

            kind = i.get('kind', "")

            if kind in ["ipv4", "domain"]:
                cef['sourceAddress'] = i['value']
            elif kind == "uri":
                cef['requestURL'] = i['value']
            elif kind == "email":
                cef['suser'] = i['value']
            elif kind in ["hash-md5", "hash-sha1", "hash-sha256", "hash-sha512"]:
                cef['cs1'] = kind
                cef['cs1Label'] = "HashType"
                cef['fileHash'] = i['value']
                cef['hash'] = i['value']
            else:
                cef['cs1'] = kind
                cef['cs1Label'] = "EIQ_Kind"
                cef['cs2'] = i['value']
                cef['cs2Label'] = "EIQ_Value"

            artifacts.append(artifact)

        return artifacts

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing EclecticIQ Intelligence Center availability.")
        
        try:
            status = self.eiq_api.get_user_status()            
            self.save_progress("Test passed, authorization and connectivity successful.")
        except Exception as e:
            self.save_progress(str(e))
            self.save_progress("Connectivity and auth test failed.")
            return action_result.get_status()
            
        if self._tip_of_id is not None:
            self.save_progress("-----------------------------------------")
            self.save_progress("Testing Outgoing Feed availability")
            outgoing_feed = self.eiq_api.get_feed_info(str(self._tip_of_id))
            
            self.save_progress(str(outgoing_feed))

            if not outgoing_feed[0]:
                self.save_progress("Outgoing Feed check Failed.")
                return action_result.get_status()

            try:
                outgoing_feed_block_list = self.eiq_api.get_feed_content_blocks(outgoing_feed[0])
                self.save_progress("Outgoing Feed is available in the Platform. There are {0} blocks inside."
                                   .format(len(outgoing_feed_block_list)))
            except Exception as e:
                self.save_progress("Cannot collect data from Outgoing Feed. Check user permissions. Exception:" + str(e))

            try:
                test_block = self.eiq_api.download_block_list(outgoing_feed_block_list[0])
                json.loads(test_block)
                self.save_progress("Content test of Outgoing Feed passed.")
            except Exception as e:
                self.save_progress("Content type test of Outgoing Feed failed."
                                   " Check Content type in Platform. Exception:" + str(e))

        if self._tip_group is not None:
            self.save_progress("-----------------------------------------")
            self.save_progress("Testing Platform Group ID resolving")

            try:
                group_id = self.eiq_api.get_source_group_uid(self._tip_group)
                self.save_progress("Test passed, group ID: " + group_id)
            except Exception as e:
                self.save_progress("Group ID Check Failed. Exception:" + str(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        domain = param['domain']

        lookup_result = self.eiq_api.lookup_observable(domain, 'domain')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'Domain not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'Domain found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_email_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        email = param['email']

        lookup_result = self.eiq_api.lookup_observable(email, 'email')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'Email not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'Email found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_file_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_hash = param['hash']
        hash_types = ["file","hash-md5","hash-sha1","hash-sha256","hash-sha512"]
        result = {}
        summary = action_result.update_summary({})
        results_count = 0
        
        for hash_type in hash_types:
            lookup_result = self.eiq_api.lookup_observable(file_hash, hash_type)
            if isinstance(lookup_result, dict):
                results_count = results_count + 1
                parsed_response = {}
                parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                    }
                result.update(parsed_response)

        if results_count > 0:
            action_result.add_data(result)
            summary['total_count'] = str(results_count)
            summary = action_result.update_summary({})
            return action_result.set_status(phantom.APP_SUCCESS, 'File hash found in EclecticIQ Platform.') 
        else:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'File hash not found in EclecticIQ Platform.')

    def _handle_ip_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param['ip']

        lookup_result = self.eiq_api.lookup_observable(ip, 'ipv4')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'IP not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'IP found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_url_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        url = param['url']

        lookup_result = self.eiq_api.lookup_observable(url, 'uri')

        if lookup_result is None:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'URL not found in EclecticIQ Platform.')

        elif isinstance(lookup_result, dict):
            parsed_response = {
                    'last_updated': lookup_result['last_updated'],
                    'maliciousness': lookup_result['maliciousness'],
                    'value': lookup_result['value'],
                    'platform_link': lookup_result['platform_link'],
                    'source_name': lookup_result['source_name'],
                    'created': lookup_result['created']
                }
            action_result.add_data(parsed_response)

            summary = action_result.update_summary({})
            summary['total_count'] = '1'

            return action_result.set_status(phantom.APP_SUCCESS, 'URL found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_create_sighting(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_group == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Group ID in asset parameters"), None)

        observables_dict = self._prepare_observables(param)

        sighting_conf_value = param['confidence_value']
        sighting_title = param['sighting_title']
        sighting_tags = param['tags'].split(",")
        sighting_impact_value = param.get('impact_value')
        sighting_description = param.get('sighting_description', "")

        sighting = self.eiq_api.create_entity(observable_dict=observables_dict, source_group_name=self._tip_group,
                                              entity_title=sighting_title, entity_description=sighting_description,
                                              entity_tags=sighting_tags, entity_confidence=sighting_conf_value,
                                              entity_impact_value=sighting_impact_value)

        action_result.add_data(sighting)
        summary = action_result.update_summary({})

        if sighting is not False:
            summary['important_data'] = 'Sighting was created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            summary['important_data'] = 'Sighting wasnt created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_create_indicator(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._tip_group == "None":
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No Group ID in asset parameters"), None)
        
        try:
            param['observable_dictionary']
        except KeyError:
            param['observable_dictionary'] = []

        observable_dict = self._prepare_entity_observables(param['observable_1_value'], 
                                                            param['observable_1_type'],
                                                            param['observable_1_maliciousness'],
                                                            param['observable_dictionary'])

        indicator_conf_value = param['confidence_value']
        indicator_title = param['indicator_title']
        indicator_tags = param['tags'].split(",")
        indicator_impact_value = param.get('impact_value')
        indicator_description = param.get('indicator_description', "")

        indicator = self.eiq_api.create_entity(observable_dict=observable_dict, source_group_name=self._tip_group,
                                              entity_title=indicator_title, entity_description=indicator_description,
                                              entity_tags=indicator_tags, entity_confidence=indicator_conf_value,
                                              entity_impact_value=indicator_impact_value, entity_type="indicator")

        action_result.add_data(indicator)
        summary = action_result.update_summary({})

        if indicator is not False:
            summary['important_data'] = 'Indicator was created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            summary['important_data'] = 'Indicator wasnt created in Threat Intelligence Platform.'
            return action_result.set_status(phantom.APP_ERROR)

    def _prepare_observables(self, param):
        observable_params = [
            (
                param['observable_1_maliciousness'],
                param['observable_1_type'],
                param['observable_1_value'],
            ),
            (
                param.get('observable_2_maliciousness'),
                param.get('observable_2_type'),
                param.get('observable_2_value'),
            ),
            (
                param.get('observable_3_maliciousness'),
                param.get('observable_3_type'),
                param.get('observable_3_value'),
            ),
        ]
        observables_list = []

        maliciousness_to_meta = {
            "Malicious (High confidence)": {
                "classification": "bad",
                "confidence": "high",
            },
            "Malicious (Medium confidence)": {
                "classification": "bad",
                "confidence": "medium",
            },
            "Malicious (Low confidence)": {
                "classification": "bad",
                "confidence": "low",
            },
            "Safe": {
                "classification": "good",
            },
            "Unknown": {
            },
        }

        for observable in observable_params:
            record = dict(
                observable_type=observable[1],
                observable_value=observable[2])

            record["observable_maliciousness"] = maliciousness_to_meta[observable[0]].get("confidence", "")
            record["observable_classification"] = maliciousness_to_meta[observable[0]].get("classification", "")

            observables_list.append(record)

        return observables_list

    def _prepare_entity_observables(self, observable1value, observable1type, observable1malicousness, observable_dict):
        """Method duplicate _prepare_observables method with difference in params names.
        Been added for backward compatibility.

        """
        
        observables_list = []
        
        maliciousness_to_meta = {
            "Malicious (High confidence)": {
                "classification": "bad",
                "confidence": "high",
            },
            "Malicious (Medium confidence)": {
                "classification": "bad",
                "confidence": "medium",
            },
            "Malicious (Low confidence)": {
                "classification": "bad",
                "confidence": "low",
            },
            "Safe": {
                "classification": "good",
            },
            "Unknown": {
            }
        }
        
        maliciousness_to_meta_dict = {
            "high": {
                "classification": "bad",
                "confidence": "high",
            },
            "medium": {
                "classification": "bad",
                "confidence": "medium",
            },
            "low": {
                "classification": "bad",
                "confidence": "low",
            },
            "safe": {
                "classification": "good",
            },
            "unknown": {
            }
        }
        
        result = []
        
        record = dict(
                observable_type=observable1type,
                observable_value=observable1value)
        
        record["observable_maliciousness"] = maliciousness_to_meta[observable1malicousness].get("confidence", "")
        record["observable_classification"] = maliciousness_to_meta[observable1malicousness].get("classification", "")
        
        result.append(record)
        
        if observable_dict:     
            split = (observable_dict.replace(" ", "")).split(";")

            for observable in split:
                observable = observable.split(",")
                record = dict(
                    observable_type=observable[1],
                    observable_value=observable[0])
        
                record["observable_maliciousness"] = maliciousness_to_meta_dict[observable[2]].get("confidence", "")
                record["observable_classification"] = maliciousness_to_meta_dict[observable[2]].get("classification", "")
            
                result.append(record)

        return result

    def _handle_query_entities(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param.get('observable', None)

        if param['entity_type'] == "all":
            entity_type = None
        else:
            entity_type = param['entity_type']
        entity_value = param.get('entity_title', None)
        query_result = self.eiq_api.search_entity(entity_value=entity_value, entity_type=entity_type, observable_value=query)

        if (type(query_result) is dict) or (type(query_result) is list): 
            output_result = []
            
            for entity in query_result:
                record = []
                record = entity
                record["observables_output"] = str(entity["observables_list"])
                record["relationships_output"] = str(entity["relationships_list"])
                output_result.append(record)
                
            action_result.add_data(output_result)

            summary = action_result.update_summary({})
            summary['total_count'] = len(query_result)

            return action_result.set_status(phantom.APP_SUCCESS, 'Entity found in EclecticIQ Platform.')
        elif query_result is False:
            summary = action_result.update_summary({})
            summary['total_count'] = '0'
            return action_result.set_status(phantom.APP_SUCCESS, 'No entities found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_query_entity_by_id(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        entity_id = param.get('entity_id', None)
        
        query_result = self.eiq_api.get_entity_by_id(entity_id)

        if type(query_result).__name__ == "Exception":
            if "Status code:404" in str(query_result):
                summary = action_result.update_summary({})
                summary['total_count'] = '0'
                return action_result.set_status(phantom.APP_SUCCESS, 'No entities found in EclecticIQ Platform.')
            else:
                return action_result.set_status(phantom.APP_ERROR)                
        elif (type(query_result) is dict) or (type(query_result) is list):          
            record = []
            record = query_result
            record["observables_output"] = str(query_result["observables_list"])
            record["relationships_output"] = str(query_result["relationships_list"])
                
            action_result.add_data(record)

            summary = action_result.update_summary({})
            summary['total_count'] = 1

            return action_result.set_status(phantom.APP_SUCCESS, 'Entity found in EclecticIQ Platform.')
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_eclecticiq_request_get(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        uri = param.get('uri', None)
        
        summary = action_result.update_summary({})

        try:
            request_result = self.eiq_api.send_api_request('get', uri)
            record = {}
            record["reply_status"] = str(request_result.status_code)
            record["reply_body"] = request_result.json()          
            
            action_result.add_data(record)
            summary['total_count'] = 1
            
            return action_result.set_status(phantom.APP_SUCCESS, 'EclecticIQ GET request been executed succefully.')
        except Exception as e:
            status_code_re = re.search('\scode\:(\d*)', str(e))
            status_code = status_code_re.group(1)
            
            record = {}
            record["reply_status"] = str(status_code)
            summary['total_count'] = 0
            action_result.add_data(record)                        
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_eclecticiq_request_delete(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        uri = param.get('uri', None)        
        summary = action_result.update_summary({})

        try:
            request_result = self.eiq_api.send_api_request('delete', uri)
            record = {}
            record["reply_status"] = str(request_result.status_code)

            action_result.add_data(record)
            summary['total_count'] = 1
            
            return action_result.set_status(phantom.APP_SUCCESS, 'EclecticIQ DELETE request been executed succefully.')
        except Exception as e:
            status_code_re = re.search('\scode\:(\d*)', str(e))
            status_code = status_code_re.group(1)
            
            record = {}
            record["reply_status"] = str(status_code)
            summary['total_count'] = 0
            action_result.add_data(record)                        
            return action_result.set_status(phantom.APP_ERROR)
        
    def _handle_eclecticiq_request_post(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        uri = param.get('uri', None)
        body = json.loads(param.get('body', None))
        
        summary = action_result.update_summary({})

        try:
            request_result = self.eiq_api.send_api_request('post', uri, data=body)
            record = {}
            record["reply_status"] = str(request_result.status_code)
            record["reply_body"] = request_result.json()          
            
            action_result.add_data(record)
            summary['total_count'] = 1
            
            return action_result.set_status(phantom.APP_SUCCESS, 'EclecticIQ POST request been executed succefully.')
        except Exception as e:
            status_code_re = re.search('\scode\:(\d*)', str(e))
            status_code = status_code_re.group(1)
            
            record = {}
            record["reply_status"] = str(status_code)
            summary['total_count'] = 0
            action_result.add_data(record)                        
            return action_result.set_status(phantom.APP_ERROR)
        
        
    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)

        elif action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param)

        elif action_id == 'email_reputation':
            ret_val = self._handle_email_reputation(param)

        elif action_id == 'create_sighting':
            ret_val = self._handle_create_sighting(param)

        elif action_id == 'create_indicator':
            ret_val = self._handle_create_indicator(param)

        elif action_id == 'query_entities':
            ret_val = self._handle_query_entities(param)

        elif action_id == 'query_entity_by_id':
            ret_val = self._handle_query_entity_by_id(param)

        elif action_id == 'eclecticiq_request_get':
            ret_val = self._handle_eclecticiq_request_get(param)

        elif action_id == 'eclecticiq_request_post':
            ret_val = self._handle_eclecticiq_request_post(param)

        elif action_id == 'eclecticiq_request_delete':
            ret_val = self._handle_eclecticiq_request_delete(param)            

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()
        # get the asset config
        config = self.get_config()

        self.eiq_api = eiqlib.EclecticIQ_api(baseurl=config['tip_uri'],
                                      eiq_api_version=config.get('tip_api', "v1"),
                                      username="",
                                      password=config['tip_password'],
                                      verify_ssl=config.get('tip_ssl_check', False),
                                      proxy_ip=config.get('tip_proxy_uri', None),
                                      proxy_password=config.get('tip_proxy_password', None),
                                      proxy_username=config.get('tip_proxy_user', None),
                                      init_cred_test=False)

        self._tip_group = config.get('tip_group', None)
        self._tip_of_id = config.get('tip_of_id', None)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = EclecticiqAppConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
