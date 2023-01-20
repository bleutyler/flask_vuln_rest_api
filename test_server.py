import unittest
import requests
import json

class SimpleRESTApiTests(unittest.TestCase):

    def setUp(self):
        self.endpoint_base = 'http://127.0.0.1:5000'
        self.valid_ips_in_csv = [ '10.128.35.79', '2.25.181.181' ]
        self.invalid_ips_in_csv = [ '1.1.1.1' ]
        self.pagination_json = { 'page': 1, 'size': 5 }
        self.headers = { "Content-Type": "application/json" }
    def test_vuln_api_responses(self):
        for ip in self.valid_ips_in_csv:
            endpoint = self.endpoint_base + f'/asset/{ip}/vulnerabilities'
            # Pagination testing
            response = requests.post(endpoint, headers=self.headers, data=json.dumps(self.pagination_json),
                                     verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"List Vulns response is not empty for ip {ip}")
            self.assertEqual(len(response_json['vulnerabilities']), self.pagination_json['size'],
                             f"List Vulns response is of size {self.pagination_json['size']} for ip {ip}")
            self.assertGreaterEqual(response_json['vulnerabilities'][1]['title'], response_json['vulnerabilities'][0]['title'],
                                    f"List Vulns response 2nd element title Greater than 1st (alphabetical sort)")

            # No Pagination testing
            response = requests.post(endpoint, headers=self.headers, data=json.dumps({}), verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"List Vulns response (no pagination) is not empty for ip {ip}")
            self.assertGreater(len(response_json['vulnerabilities']), self.pagination_json['size'],
                             f"List Vulns response (no pagination) is greater than pagination size for ip {ip}")
            self.assertGreaterEqual(response_json['vulnerabilities'][1]['title'], response_json['vulnerabilities'][0]['title'],
                              f"List Vulns response (no pagination) 2nd element title Greater than 1st (alphabetical sort)")

        for ip in self.invalid_ips_in_csv:
            endpoint = self.endpoint_base + f'/asset/{ip}/vulnerabilities'
            response = requests.post(endpoint, headers=self.headers, data=json.dumps(self.pagination_json), verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"List Vulns response is not empty for ip {ip}")
            self.assertRegexpMatches(response_json['msg'], 'no vulnerability',
                                     'List Vulns graceful message if IP not found')



    def test_top_vuln_api_responses(self):
        for ip in self.valid_ips_in_csv:
            endpoint = self.endpoint_base + f'/asset/{ip}/top10'
            # Pagination testing
            response = requests.post(endpoint, headers=self.headers, data=json.dumps(self.pagination_json), verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"Top 10 Vulns response is not empty for ip {ip}")
            self.assertEqual(len(response_json['vulnerabilities']), self.pagination_json['size'],
                             f"Top 10 Vulns response is of size {self.pagination_json['size']} for ip {ip}")
            self.assertGreaterEqual(response_json['vulnerabilities'][0]['risk'],
                                    response_json['vulnerabilities'][1]['risk'],
                                    f"Top 10 Vulns response  1st element risk Greater than 2nd (risk sort)")


            # No Pagination testing
            response = requests.post(endpoint, headers=self.headers, data=json.dumps({}), verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"Top 10 Vulns response (no pagination) is not empty for ip {ip}")
            self.assertEqual(len(response_json['vulnerabilities']), 10,
                             f"Top 10 Vulns response (no pagination) is of size 10 for ip {ip}")
            self.assertGreaterEqual(response_json['vulnerabilities'][0]['risk'],
                                    response_json['vulnerabilities'][1]['risk'],
                                    f"Top 10 Vulns response (no pagination) 1st element risk Greater than 2nd (risk sort)")

        for ip in self.invalid_ips_in_csv:
            endpoint = self.endpoint_base + f'/asset/{ip}/top10'
            response = requests.post(endpoint, headers=self.headers, data=json.dumps(self.pagination_json), verify=False)
            response_json = json.loads(response.text)
            self.assertIsNotNone(response_json, f"Top 10 Vulns response is not empty for ip {ip}")
            self.assertRegexpMatches(response_json['msg'], 'no vulnerability', 'Top 10 Vulns graceful message if IP not found')


if __name__ == '__main__':
    unittest.main()
