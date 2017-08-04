import requests
import re

def request_by_ip(ip):
    response = {}
    request = requests.get("http://www.fairplay.ac/lookup/address/{}".format(ip))
    assert request.status_code == 200
    output = re.findall("Fairplay Guid: ([a-zA-Z0-9]{5})", request.text)
    if len(output) == 0:
        return None
    response["guid"] = output[0]

    response["fairshots"] = re.findall("reportFairshot\('(.*?)','(.*?)','(.*?)','(.*?)','(.*?)'", request.text)
    return response