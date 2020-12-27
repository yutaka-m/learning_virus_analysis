import urllib.parse
import urllib.request
import json
import sys

hash_value = sys.argv[1]
vt_url = "https://www.virustotal.com/vtapi/v2/file/report"
api_key = "<YOUR-API-KEY>"
parameters = {'apikey': api_key, 'resource': hash_value}
print(parameters)
encoded_parameters = urllib.parse.urlencode(parameters).encode("ascii")
request = urllib.request.Request(vt_url, encoded_parameters)
response = urllib.request.urlopen(request)
json_response = json.loads(response.read())
if json_response['response_code']:
    detections = json_response['positives']
    total = json_response['total']
    scan_results = json_response['scans']
    print("Detections: %s/%s" % (detections, total))
    print("VirusToral Results:")
    for av_name, av_data in scan_results.items():
        print("\t%s ==> %s" % (av_name, av_data['result']))
else:
    print("No AV Detections For: %s" % hash_value)

