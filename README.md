# flask_vuln_rest_api

This is a Python Flask implementation of a REST API for checking vuln information

## Setup

Windows:

<pre>set FLASK_APP=server.py</pre>

Update the **config.py** file *host* and *port* to make sure they are correct.
Currently set to the defaults: 

| | Value|
| --- | --- |
| Default IP | 127.0.0.1 |
| Default Port | 5000 |

## Run Server

To Execute, run the following in the folder of the application:

<pre>python -m flask run</pre>

# Usage

## Endpoints

### [POST] /asset/<ip_address>/vulnerabilities

Will request the list of vulnerability findings on the host at IP address **<ip_address>**.  
Supports pagination (see Request Body)

#### Request body (JSON)
<pre>
{
    'page': integer,
    'size': integer
}
</pre>

#### Response body (JSON)

Returns a list of vulnerability findings, in alphabetical order.  A vulnerability finding is an id, title and risk value

<pre>
{
    'vulnerabilities': 
        [
            {
                'id': string,
                'title': string,
                'risk': integer
            }
        ]
}
</pre>

### [POST] /asset/<ip_address>/top\<number\>

Will request the list of the top **\<number\>** vulnerability findings on the host at IP address **<ip_address>** 
based on the risk value of the vulnerability finding.  
Supports pagination (see Request Body)

#### Request body (JSON)
<pre>
{
    'page': integer,
    'size': integer
}
</pre>

#### Response body (JSON)

Returns a list of vulnerability findings, in descending order of risk.  
A vulnerability finding is an id, title and risk value.

<pre>
{
    'vulnerabilities': 
        [
            {
                'id': string,
                'title': string,
                'risk': integer
            }
        ]
}
</pre>

### Response body when unable to fulfill request (JSON)

If the request cannot be processed, such as the IP address is not in the data, then the following is returned:

<pre>
{
    'msg': 'string containing error message'
}
</pre>


## Testing

### Python Unit Testing


Unit testing provided in sample script: <pre>test_server.py</pre>
These unit tests must be run with the flask application running.


### POSTMAN

Tested in Postman to simulate JSON HTTP POST Requests

Postman Collection of valid request with pagination:

https://api.postman.com/collections/25385639-1963ca67-bf4f-4ef5-aad0-66a8a1539e26?access_key=PMAT-01GQ7V0PYRH3P0VFH4E8P7000Y

### Assumptions

An Upstream process will update the contents of vulnerabilities.csv

For the sake of this project, it will be designed to just fulfill the 2 listed functions in the Requirements document.  
- Only HTTP POST implemented, not HTTP GET, HTTP DELETE, HTTP PUT
- No other endpoints implemented (ex. http://127.0.0.1/ not implemented)

### Notes

vulnerabilities.csv was renamed from vulnerabilities(fixed).csv
