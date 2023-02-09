import requests
import json
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor

def main():
    if len(sys.argv) == 1:
        print('''   You are missing needed parameters.\n\n   Use '-h' for help''')
    elif sys.argv[1] == '-h':
        print('''   3 parameters are required:\n   1. Environment: 'prod' or 'rc\n   2. CVE Source: 'NVD' or "OSSINDEX'\n   3. CVE ID: NVD or OSSINDEX CVE ID\n\n   Example: python3 app.py rc nvd cve-2022-22965''')
    else:
        _environment = sys.argv[1].upper()
        _cve_source = sys.argv[2].upper()
        # to handle OSSINDEX IDs vs CVE-# need the following
        if "cve-" in sys.argv[3]:
            _recast_cve = sys.argv[3].upper()
        else:
            _recast_cve = sys.argv[3]

        # Pass user params to gather_info()
        gather_info(_environment,_cve_source,_recast_cve)


def gather_info(_environment,_cve_source,_recast_cve):

    components_list = []
    component_versions_list = []
    projects_list = []
    active_projects_list = []
    DT_PROD_API_KEY = os.environ['DT_PROD_API_KEY']
    DT_RC_API_KEY = os.environ['DT_RC_API_KEY']

    if _environment == "PROD":
        _api_key = DT_PROD_API_KEY
        _url_cve = "https://sca.cicd.au-infrastructure.com/api/v1/vulnerability/source/"+_cve_source+"/vuln/"+_recast_cve
        _url_analysis = "https://sca.cicd.au-infrastructure.com/api/v1/analysis"
    if _environment == "RC":
        _api_key = DT_RC_API_KEY
        _url_cve = "https://sca-rc.cicd.au-infrastructure.com/api/v1/vulnerability/source/"+_cve_source+"/vuln/"+_recast_cve
        _url_analysis = "https://sca-rc.cicd.au-infrastructure.com/api/v1/analysis"

    headers = {
        'x-api-key': _api_key,
        'Content-Type': 'application/json'
    }

    response = requests.request("GET", _url_cve, headers=headers, data='')
    dt_data = json.loads(response.text)

    # Multi-threading to analysis false_positive_func
    with ThreadPoolExecutor(max_workers=15) as executor:
        results = {}
        results['metadata'] = {}

        start = time.time()

        for i in dt_data['components']:
            ### IF there is a specific version to whitelist > set in next line and indent rest of lines
            # if (i['version'] == "5.3.25") or (i['version'] == "5.3.24") or (i['version'] == "5.3.23") or (i['version'] == "5.3.20") or (i['version'] == "5.3.18"): #CVE-2016-1000027
            # if (i['version'] == "1.33"): #CVE-2022-1471
            # if (i['version'] == "1.9.2"): #CVE-2019-10172
            # if (i['version'] == "0.6.2"): #CVE-2016-3720 & CVE-2016-7051
            # if (i['version'] == "3.3.0") or (i['version'] == "4.0.0") or (i['version'] == "3.4.2") or (i['version'] == "2.1.3"): #CVE-2022-21222 - https://security.snyk.io/vuln/SNYK-JS-CSSWHAT-3035488

            # individual vuln ID, component and project
            vuln_id = dt_data['uuid']
            component_id = i['uuid']
            project_id = i['project']['uuid']
            # Print list of active projects
            if i['project']['active'] == True:
                if i.get('project').get('name') == None:
                    # print(i.get('project').get('uuid'))
                    active_projects_list.append(i['project']['uuid'])
                else:
                    # print(i.get('project').get('name'))
                    active_projects_list.append(i['project']['uuid'])
            projects_list.append(i['project']['uuid'])
            components_list.append(i['uuid'])
            component_versions_list.append(i['version'])
            # multi-thread action
            executor.submit(false_positive_func,vuln_id,project_id,component_id,_url_analysis,_api_key)

    end = time.time()
    results['metadata']['total_execution_time'] = end - start
    results['metadata']['unique projects'] = len(set(projects_list))
    results['metadata']['active projects'] = len(set(active_projects_list))
    results['metadata']['unique components'] = len(set(components_list))
    results['metadata']['unique component versions'] = len(set(component_versions_list))
    results['metadata']['unique component versions'] = set(component_versions_list)
    print(results)


def false_positive_func(vuln_id,project_id,component_id, _url_analysis, _api_key):

  payload = json.dumps({
    "project": project_id,
    "component": component_id,
    "vulnerability": vuln_id,
    "analysisState": "FALSE_POSITIVE",
    "analysisJustification": "NOT_SET",
    "analysisResponse": "NOT_SET",
    "analysisDetails": None,
    "comment": "https://autonomic-ai.atlassian.net/browse/SE-972",
    "isSuppressed": True
  })
  headers = {
    'x-api-key': _api_key,
    'Content-Type': 'application/json'
  }

  response = requests.request("PUT", _url_analysis, headers=headers, data=payload)

  return(response.text)


main()