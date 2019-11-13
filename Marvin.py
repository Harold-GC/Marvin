#!/usr/bin/env python2

import json
import os
import random
import requests
import sys
import traceback
import pprint
import urllib3
import argparse


class ApiConnector():
    def __init__(self, server_ip_address, username, password):

        self.server_ip_address = server_ip_address
        self.username = username
        self.password = password
        BASE_URL = 'https://%s:9440/PrismGateway/services/rest/%s'
        URL_API_V1 = 'v1/'
        URL_API_V2 = 'v2.0/'
        self.base_url_api_v1 = BASE_URL % (self.server_ip_address, URL_API_V1)
        self.base_url_api_v2 = BASE_URL % (self.server_ip_address, URL_API_V2)
        self.session = self.get_server_session(self.username, self.password)

    def get_server_session(self, username, password):

        session = requests.Session()
        session.auth = (username, password)
        session.verify = False
        session.headers.update(
            {'Content-Type': 'application/json; charset=utf-8'})
        return session

    def _call_rest_api_get(self, api_url, apicall):
        cluster_url = api_url + apicall
        print("INFO: call_rest_api_get: API Call %s" %
              cluster_url)
        server_response = self.session.get(cluster_url)
        return server_response.status_code, json.loads(server_response.text)

    def _call_rest_api_post(self, api_url, apicall, json_data):
        cluster_url = api_url + apicall
        print("INFO: call_rest_api_post: API Call %s" %
              cluster_url)
        server_response = self.session.post(cluster_url, data=json_data)
        return server_response.status_code, json.loads(server_response.text)

    def call_rest_api_v1_get(self, apicall):
        return self._call_rest_api_get(self.base_url_api_v1, apicall)

    def call_rest_api_v1_post(self, apicall, json_data):
        return self._call_rest_api_post(self.base_url_api_v1, apicall,
                                        json_data)

    def call_rest_api_v2_get(self, apicall):
        return self._call_rest_api_get(self.base_url_api_v2, apicall)

    def call_rest_api_v2_post(self, apicall, json_data):
        return self._call_rest_api_post(self.base_url_api_v2, apicall,
                                        json_data)


class ConfigConnector():
    def __init__(self, cfg_file):
        self.cfg_file = cfg_file
        cfg_json = open(cfg_file).read()
        self.configuration = json.loads(cfg_json)

    def get_config_param(self, config_item, config_param):
        return self.configuration[config_item][config_param]

    def set_config_param(self, config_item, config_param, param_value):
        self.configuration[config_item][config_param] = param_value

    def set_internal_network_uuid(self, config_item, uuid):
        self.configuration[config_item]['files_configuration']['internalNetwork']['uuid'] = uuid

    def set_external_network_uuid(self, config_item, uuid):
        self.configuration[config_item]['files_configuration']['externalNetworks'][0]['uuid'] = uuid


class ClusterConfigurator():
    def __init__(self, api_con):
        self.api_con = api_con

    def new_public_key(self, key_name, key_string):
        new_key_json = json.dumps({'name': key_name,
                                   'key': key_string})
        print("INFO: new_public_key: Creating new public key with info: " +
              new_key_json)
        status_code, json_response = self.api_con.call_rest_api_v2_post(
            "cluster/public_keys", new_key_json)
        return json_response


class NetConfigurator():
    def __init__(self, api_con):
        self.api_con = api_con
        self.networks = self.get_networks()

    def get_networks(self):
        status, networks = self.api_con.call_rest_api_v2_get(
            "networks")
        return networks['entities']

    def _get_network_by_attribute(self, net_attr, attr_value):
        self.networks = self.get_networks()
        network_match = []
        for network in self.networks:
            if network[net_attr] == attr_value:
                network_match.append(network)
        return network_match

    def get_network_by_vlan(self, vlan_id):
        return self._get_network_by_attribute("vlan_id", vlan_id)

    def get_network_by_name(self, net_name):
        return self._get_network_by_attribute("name", net_name)

    def get_network_by_uuid(self, network_uuid):
        return self._get_network_by_attribute("uuid", network_uuid)

    def exist_network_with_vlan(self, network_vlan):
        for network in self.networks:
            if network['vlan_id'] == network_vlan:
                return True
        return False

    def exist_network_with_name(self, network_name):
        for network in self.networks:
            if network['name'] == network_name:
                return True
        return False

    def is_managed_network(self, network_uuid):
        [network] = self.get_network_by_uuid(network_uuid)
        if network['ip_config']['prefix_length']:
            return True
        return False

    def create_network(self, network_name, network_vlan):
        new_network_json = json.dumps({'name': network_name,
                                       'vlan_id': network_vlan})

        print("INFO: create_network: Creating network with info: " +
              new_network_json)
        status_code, json_response = self.api_con.call_rest_api_v2_post(
            "networks", new_network_json)
        print("INFO: create_network: status code " + str(status_code) +
              ". New network UUID: " + json_response['network_uuid'])
        return json_response['network_uuid']


class FilesConfigurator():
    def __init__(self, api_con):
        self.api_con = api_con
        self.files = ""

    def software_download(self, files_version):
        new_files_json = json.dumps({'name': files_version,
                                     'version': files_version})
        print("INFO: software_download: Downloading files with info: " +
              new_files_json)
        status_code, json_response = self.api_con.call_rest_api_v2_post(
            "upgrade/afs/softwares/" + files_version + "/download", new_files_json)
        return json_response

    def deploy_files_server(self, files_config_json):
        print("INFO: deploy_files_server: Deploying files server with info: " +
              json.dumps(files_config_json))
        status_code, json_response = self.api_con.call_rest_api_v1_post(
            "vfilers", json.dumps(files_config_json))
        return json_response


class DeploymentOrchestrator():
    def __init__(self, config_file):
        self.cfg_con = ConfigConnector(config_file)
        self.api_con = ApiConnector(
            self.cfg_con.get_config_param(0, 'cluster_external_ipaddress'),
            self.cfg_con.get_config_param(0, 'username'),
            self.cfg_con.get_config_param(0, 'password')
        )
        self.net_conf = NetConfigurator(self.api_con)
        self.cluster_config = ClusterConfigurator(self.api_con)
        self.files_config = FilesConfigurator(self.api_con)

    def deploy_network(self):
        exist_net_with_vlan = self.net_conf.exist_network_with_vlan(
            int(self.cfg_con.get_config_param(0, 'network_vlan')))
        is_managed = True

        if exist_net_with_vlan:
            files_network = self.net_conf.get_network_by_vlan(
                int(self.cfg_con.get_config_param(0, 'network_vlan')))
            print("INFO: main: network exist with vlan: " +
                  files_network[0]['uuid'])
            is_managed = self.net_conf.is_managed_network(
                files_network[0]['uuid'])

        if is_managed:
            print("INFO: main: Creating new network")
            files_network_uuid = self.net_conf.create_network(
                self.cfg_con.get_config_param(0, 'network_name'),
                self.cfg_con.get_config_param(0, 'network_vlan'))
            files_network = self.net_conf.get_network_by_uuid(
                files_network_uuid)

        else:
            print("INFO: main: Unmanaged network with vlan {0} already exist.".format(
                self.cfg_con.get_config_param(0, 'network_vlan')))
            print("INFO: main: Using network '{0}' with uuid: '{1}' instead".format(
                files_network[0]['name'], files_network[0]['uuid']))
            self.cfg_con.set_config_param(
                0, 'network_name', files_network[0]['name'])
        return True

    def deploy_ssh_key(self):
        self.cluster_config.new_public_key(
            self.cfg_con.configuration[0]['pub_key_name'],
            self.cfg_con.configuration[0]['pub_key_string'])
        return True

    def deploy_files(self):
        files_network = self.net_conf.get_network_by_vlan(
            int(self.cfg_con.get_config_param(0, 'network_vlan')))

        self.cfg_con.set_internal_network_uuid(
            0, files_network[0]['uuid'])
        self.cfg_con.set_external_network_uuid(
            0, files_network[0]['uuid'])

        self.files_config.software_download(
            self.cfg_con.configuration[0]['files_software_version'])
        self.files_config.deploy_files_server(
            self.cfg_con.configuration[0]['files_configuration'])


if __name__ == "__main__":
    try:

        urllib3.disable_warnings()

        # ==========
        parser = argparse.ArgumentParser(
            description='Deploy a file server in a nutanix cluster.',
            epilog='"And then, of course, I\'ve got this terrible pain in all the \
            diodes down my left side."')
        parser.add_argument('config_file', metavar='<config_file>', type=str,
                            help='an integer for the accumulator')
        parser.add_argument('-k', '--add_pub_key', dest='add_pub_key',
                            action='store_true',
                            help='Add public key to cluster.')
        parser.add_argument('-n', '--create_network', dest='create_network',
                            action='store_true',
                            help='Add public key to cluster.')
        parser.add_argument('-f', '--deploy_files', dest='deploy_files',
                            action='store_true',
                            help='Deploy instance of file server.')

        args = parser.parse_args()

        print("=" * 79)
        deploy = DeploymentOrchestrator(args.config_file)
        if args.add_pub_key:
            deploy.deploy_ssh_key()

        if args.create_network:
            deploy.deploy_network()

        if args.deploy_files:
            deploy.deploy_files()
        # ==========
        print("=" * 79)

    except Exception as ex:
        print(ex)
        sys.exit(1)
