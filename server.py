from flask import Flask, request
import json
import config
import csv
from os import path

vuln_api = Flask(__name__)

@vuln_api.route('/', methods=['GET'])
def get_home():
    return 'Hello Tyler'

@vuln_api.route('/asset/<ip_address>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(ip_address: str):
    source_json = None
    try:
        source_json = request.get_json()
        host_vulns = ingest_csv_data(ip_address)
        if (len(host_vulns) == 0):
            return { 'msg': f'no vulnerability data for host {ip_address}'}
        return_list = []
        for vuln in host_vulns.keys():
            return_list.append(host_vulns[vuln])
        print(f"*************************************\n")
        print(f"JSON: Page index is: {source_json['page']} ")
        print(f"and page_size = {source_json['size']}\n")
        print(f"*************************************\n")
        if (source_json['page'] != "" and source_json['size'] != "" ):
            page_index = int(source_json['page'])
            page_size = int(source_json['size'])
            return {'vulnerabilities': return_list[page_index:page_size]}
        else:
            return {'vulnerabilities': return_list}
    except ():
        return_string = ""
        return_string += f"*************************************\n"
        return_string += f"JSON: Page index is: {source_json['page']} "
        return_string += f"and page_size = {source_json['size']}\n"
        return_string += f"*************************************\n"
        #return_string += f"{dir(request)}\n"
        return return_string

    # we know we have a JSON request at this point

@vuln_api.route('/asset/<ip_address>/top<number>', methods=['GET'])
def get_top_vulnerabilities_by_risk():
    # Just do the work of the default vulns page
    return { 'msg': 'Double Dutch Bus' }

def ingest_csv_data(host_ip: str) -> dict:
    '''
    Return a dictionary of vulns found on a host
    :param host_ip:
    :return:
    '''
    return_dict = {}
    if (not path.exists(config.source_csv_file)):
        print(f"Unable to open source file: '{config.source_csv_file}'")
        raise ValueError(f"VulnerabilityDatabase: Error with Source")
    if (host_ip == None or host_ip == ""):
        raise Exception("Cannot retrieve information on an IP tat was not provided")
    with open(config.source_csv_file) as csv_file_handle:
        csv_contents_reader = csv.reader(csv_file_handle)
        for row in csv_contents_reader:
            row_ip = row[config.csv_column_ip]
            # Do not process if it is not the IP we care about
            if (row_ip == host_ip):
                vuln_details_dict = {}
                vuln_details_dict['risk'] = int(row[config.csv_column_risk])
                vuln_details_dict['title'] = row[config.csv_column_vuln_title]
                vuln_id = row[config.csv_column_vuln_id]
                return_dict[vuln_id] = vuln_details_dict
    return return_dict

def sort_vulnerabilities_dict_by_name( vuln_dict: dict):
    pass
def sort_vulnerabilities_dict_by_risk(vuln_dict: dict):
    pass
