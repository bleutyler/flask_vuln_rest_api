from flask import Flask, request
import config
import csv
from os import path

vuln_api = Flask(__name__)

@vuln_api.route('/asset/<ip_address>/vulnerabilities', methods=['GET', 'POST'])
def get_vulnerabilities(ip_address: str):
    source_json = None
    try:
        source_json = request.get_json()
        host_vulns = ingest_csv_data_for_host(ip_address)
        if (len(host_vulns) == 0):
            return { 'msg': f'no vulnerability data for host {ip_address}'}
        # sort the host_vulns alphabetically based on vuln_title
        return_list = [ finding for finding in sorted( host_vulns, key=lambda item: item['title']) ]

        if ('page' in source_json and source_json['page'] != ""
                and 'size' in source_json and source_json['size'] != "" ):
            page_size = int(source_json['size'])
            page_index = int(source_json['page']) * page_size
            print(f"JSON: Page index is: {source_json['page']} ")
            print(f"and page_size = {source_json['size']}\n")
            print(f" so asking for {page_index} to {page_index+page_size}")
            print(f"size of return array is: {len(return_list[page_index:(page_index + page_size)])}.")
            print(f" when full set of vulns is size: {len(return_list)}.")
            return {'vulnerabilities': return_list[page_index:(page_index + page_size)]}
        else:
            return {'vulnerabilities': return_list}
    except ():
        return { "msg": "Internal Server Error"}

@vuln_api.route('/asset/<ip_address>/top<list_size>', methods=['GET', 'POST'])
def get_top_vulnerabilities_by_risk(ip_address:str, list_size:int):
    # Just do the work of the default vulns page
    source_json = None
    try:
        source_json = request.get_json()
        host_vulns = ingest_csv_data_for_host(ip_address)
        if (len(host_vulns) == 0):
            return { 'msg': f'no vulnerability data for host {ip_address}'}
        # sort the host_vulns on vuln_risk, highest risk at the front
        return_list = [ finding for finding in sorted( host_vulns, key=lambda item: item['risk'], reverse=True) ]
        return_list = return_list[0:int(list_size)]

        if ('page' in source_json and source_json['page'] != ""
                and 'size' in source_json and source_json['size'] != "" ):
            page_size = int(source_json['size'])
            page_index = int(source_json['page']) * page_size
            return {'vulnerabilities': return_list[page_index:(page_index + page_size)]}
        else:
            return {'vulnerabilities': return_list}
    except ():
        return { "msg": "Internal Server Error"}

def ingest_csv_data_for_host(host_ip: str) -> dict:
    '''
    Return a list of vulns found on a host from a CSV file
    :param host_ip: only return results for this host, returns empty list if this is blank
    :return:
        [
            {
                'id': '<vuln_id1>',
                'risk': <risk1>,
                'title': '<vuln_title1>'
            }
        ]
    '''
    return_list = []
    if (not path.exists(config.source_csv_file)):
        print(f"Unable to open source file: '{config.source_csv_file}'")
        raise ValueError(f"VulnerabilityDatabase: Error with Source")
    if (host_ip == None or host_ip == ""):
        raise Exception("Cannot retrieve information on an IP that was not provided")
    # Assemble an object based on the data in the CSV file
    with open(config.source_csv_file) as csv_file_handle:
        csv_contents_reader = csv.reader(csv_file_handle)
        for row in csv_contents_reader:
            row_ip = row[config.csv_column_ip]
            if (row_ip == host_ip):
                vuln_details_dict = {}
                vuln_details_dict['risk'] = int(row[config.csv_column_risk])
                vuln_details_dict['title'] = row[config.csv_column_vuln_title]
                vuln_details_dict['id'] = row[config.csv_column_vuln_id]
                return_list.append( vuln_details_dict )
    return return_list


if __name__ == '__main__':
    vuln_api.run(host=config.host_ip, port=config.host_port)