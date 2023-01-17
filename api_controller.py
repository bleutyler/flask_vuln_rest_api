from flask import Flask

vuln_api = Flask(__name__)

@vuln_api.route('/')
def get_home():
    return 'Hello Tyler'