# Recasting vulnerabilities by ID

## Assessed Vulnerabilities:
| CVE | Description | 
| ----------- | ----------- |
| CVE-2016-1000027 | Ensure component version is 5.3.16 and above |
| CVE-2022-22965 | Not affected - WAR deployments | 
| 6795ec44-f810-47aa-a22e-5d817e52cbdc | CVE-2022-22965 alias OSSINDEX |
| CVE-2021-0341 | False Positive |
| CVE-2022-1471 | Not Affected when v 1.33 AND (not used in code OR SafeConstructor() is implemented) |
| CVE-2021-26291 | Not affected as we use JFrog as artifactory |
| CVE-2022-41862 | RESERVED - reassess every 30 days | 

## How to run
```
export DT_PROD_API_KEY="KEY"
export DT_RC_API_KEY="KEY"

python3 recast-cve-by-id.py -h
   3 parameters are required:
   1. Environment: 'prod' or 'rc
   2. CVE Source: 'NVD' or "OSSINDEX'
   3. CVE ID: NVD or OSSINDEX CVE ID

   Example: python3 app.py rc nvd cve-2022-22965
```

## Version Specific Recasts:
1. Uncomment line (61-65)
2. Indent in next block (lines 67-83)

## IMPROVEMENTS
> Need to write logic to read CVE to recast from a YAML/JSON file stored in repo
