#!/usr/bin/python3
#
# ioc_explorer.py
# Purpose: This script can be used to find potential IOCs (IP address, domain name, or urls) in a provided log line and utilizes the VirusTotal API to provide more context on the potential IOCs.
# Python 3.X


import argparse, requests
import time, sys, json, re, getpass

#### Configure commandline options ####
#
#

parser = argparse.ArgumentParser(description='Find potential IOCs (IP address, domain name, or urls) in a provided log line and utilizes the VirusTotal API to provide more context on the potential IOCs.')
parser.add_argument('-l', '--line', help='Specify a log line sample in single or double quotes', dest='line', required=False)

#
#
####

#### Function Definitions ####
#
#

# Helper function to provide information to user
def displayStartText():
    print("\nRunning ioc_reviewer...")
    time.sleep(0.5)

# Helper function to remove duplicate potential IOCs
def removeDuplicates(items):
    deduped = set()
    for item in items:
        deduped.add(item)

    return list(deduped)

# Use regex to find any IPv4 addresses in provided sample
def findIps(line):
    ips = re.findall('\d+\.\d+\.\d+\.\d+',line)

    return removeDuplicates(ips)

# Use regex to find any com, org, or net domain names
def findDomainNames(line):
    domainNames = re.findall(r'\w+\.(?:com|org|net)',line)

    return removeDuplicates(domainNames)

# Use regex to find http and https urls
def findUrls(line):
    urls = re.findall('http(?:|s)://[^"]+',line)

    return removeDuplicates(urls)

# Make an ip address api call to Virus Total
def getIpReport(ipAddr, apiKey):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey':apiKey, 'ip':ipAddr}
    response = requests.get(url, params=params)
    print(json.dumps(response.json(), indent=4))

# Make a domain api call to Virus Total
def getDnReport(domainName, apiKey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey':apiKey, 'domain':domainName}
    response = requests.get(url, params=params)
    print(json.dumps(response.json(), indent=4))

# Make a url based api call to Virus Total
def getUrlReport(url, apiKey):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey':apiKey, 'resource':url, 'scan':1}
    response = requests.get(url, params=params)
    print(json.dumps(response.json(), indent=4))

# Function to orchestrate querying Virus Total every 15 seconds
def searchForIocs(iocs, apiKey):
    print("Using public API, I will make 4 API calls per minute...")

    counter = 0

    for ipAddr in iocs['ipAddrs']:
        print("Seaching for IP: %s..." % ipAddr)
        getIpReport(ipAddr, apiKey)
        counter += 1
        if counter < len(iocs['ipAddrs']) or len(iocs['domainNames']) > 0 or len(iocs['urls']) > 0:
            print("Pausing for 15 seconds...")
            time.sleep(15)

    counter = 0
    for domainName in iocs['domainNames']:
        print("Searching for Domain Name: %s" % domainName)
        getDnReport(domainName, apiKey)
        counter += 1
        if counter < len(iocs['domainNames']) or len(iocs['urls']) > 0:
            print("Pausing for 15 seconds...")
            time.sleep(15)

    counter = 0
    for url in iocs['urls']:
        print("Searching for url: %s" % url)
        getUrlReport(url, apiKey)
        counter += 1
        if counter < len(iocs['urls']):
            print("Pausing for 15 seconds...")
            time.sleep(15)

# Manage potential IOC discovery for log sample provided from user
def processLine(line):
    iocs['ipAddrs'] = findIps(line)
    iocs['domainNames'] = findDomainNames(line)
    iocs['urls'] = findUrls(line)

    return iocs

#
#
####

#### Script Start ####
#
#
# Parse and process options
try:
    if __name__ == "__main__":
        # Parse argparse arguments
        args = vars(parser.parse_args())

        # Interpret options
        if args['line']:
            # {'ipAddrs': [], 'domainNames': [], 'urls': []}
            iocs = {}
            displayStartText()
            print("\nSearching for IOCs...")

            iocs = processLine(args['line'])

            total = 0

            print("Search completed! I found: ")
            print("IP Addresses: %d" % len(iocs['ipAddrs']))
            total += len(iocs['ipAddrs'])

            print("Domain Names: %d" % len(iocs['domainNames']))
            total += len(iocs['domainNames'])

            print("URLs: %d" % len(iocs['urls']))
            total += len(iocs['urls'])

            if total == 0:
                print("No IOCs found...")
            else:
                print("Running VirusTotal queries...")
                apiKey = getpass.getpass("VirusTotal API Key: ")
                searchForIocs(iocs, apiKey)
            print("IOC Review Completed!")
        else:
            print("\nOooops! No actionable arguments supplied....let me run the help for you\n")
            time.sleep(1)
            parser.print_help()

# Properly hanle exceptions
except (KeyboardInterrupt):
    print('terminated.')
sys.exit(0)

#
#
####
