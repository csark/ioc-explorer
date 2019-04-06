# IOC Explorer
This directory contains a script to find potential IOCs (IP address, domain name, or urls) in a provided log line and utilizes the VirusTotal API to provide more context on the potential IOCs.

### Setup
- Run ````pip3 install -r requirements.txt````

### Usage
See the following example on how to use this script:

````
python3 ioc_reviewer.py -l '95.85.39.96 - - [25/Jul/2017:15:00:07 -0700] "GET /phpmyadmin/sql.php?table=customers&pos=0&token=73f8ba7a148b5d171780f717d9c3875d&ajax_request=true&ajax_page_request=true&_nocache=15010200074112488 HTTP/1.1" 200 13401 "http://72.44.32.129/phpmyadmin/db_structure.php?db=classicmodels&token=73f8ba7a148b5d171780f717d9c3875d" "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:54.0) Gecko/20100101 Firefox/54.0"'
````
This will output:
````
Running ioc_reviewer...

Searching for IOCs...
Search completed! I found:
IP Addresses: 2
Domain Names: 0
URLs: 1
Running VirusTotal queries...
Using public API, I will make 4 API calls per minute...
Seaching for IP: 95.85.39.96...
{
    "as_owner": "Digital Ocean, Inc.",
    "detected_urls": [],
    "response_code": 1,
    "asn": 200130,
    "resolutions": [
        {
            "last_resolved": "2018-09-09 21:38:36",
            "hostname": "hnckilit.com"
        }
    ],
    "verbose_msg": "IP address in dataset",
    "country": "NL"
}
Pausing for 15 seconds...
Seaching for IP: 72.44.32.129...
{
    "as_owner": "Amazon.com, Inc.",
    "undetected_referrer_samples": [
        {
            "positives": 0,
            "sha256": "fd35d2830170d1e9ac4af24611543a8b33478fe14ac2f2b452cdad1e46bdb107",
            "total": 58
        }
    ],
    "undetected_urls": [],
    "detected_urls": [],
    "undetected_downloaded_samples": [],
    "resolutions": [],
    "response_code": 1,
    "asn": "14618",
    "verbose_msg": "IP address in dataset",
    "detected_downloaded_samples": [],
    "country": "US"
}
Pausing for 15 seconds...
Searching for url: http://72.44.32.129/phpmyadmin/db_structure.php?db=classicmodels&token=73f8ba7a148b5d171780f717d9c3875d
{
    "scan_id": "81a7699f502abfc4c916eb4526965835cb00e2090bc123f3351741ba55bd5893-1524652209",
    "resource": "https://www.virustotal.com/vtapi/v2/url/report",
    "total": 67,
    "response_code": 1,
    "url": "https://www.virustotal.com/vtapi/v2/url/report",
    "filescan_id": null,
    "scan_date": "2018-04-25 10:30:09",
    "positives": 0,
    "permalink": "https://www.virustotal.com/url/81a7699f502abfc4c916eb4526965835cb00e2090bc123f3351741ba55bd5893/analysis/1524652209/",
    "verbose_msg": "Scan finished, scan information embedded in this object",
    "scans": {
        "Dr.Web": {
            "result": "clean site",
            "detected": false
        },
        "VX Vault": {
            "result": "clean site",
            "detected": false
        },
        "Forcepoint ThreatSeeker": {
            "result": "clean site",
            "detected": false
        },
        "OpenPhish": {
            "result": "clean site",
            "detected": false
        },
        "SecureBrain": {
            "result": "clean site",
            "detected": false
        },
        "Baidu-International": {
            "result": "clean site",
            "detected": false
        },
        "ZeusTracker": {
            "result": "clean site",
            "detail": "https://zeustracker.abuse.ch/monitor.php?host=www.virustotal.com",
            "detected": false
        },
        "Antiy-AVL": {
            "result": "clean site",
            "detected": false
        },
        "URLQuery": {
            "result": "clean site",
            "detected": false
        },
        "securolytics": {
            "result": "clean site",
            "detected": false
        },
        "NotMining": {
            "result": "unrated site",
            "detected": false
        },
        "ZCloudsec": {
            "result": "clean site",
            "detected": false
        },
        "DNS8": {
            "result": "clean site",
            "detected": false
        },
        "ESET": {
            "result": "clean site",
            "detected": false
        },
        "Tencent": {
            "result": "clean site",
            "detected": false
        },
        "ZeroCERT": {
            "result": "clean site",
            "detected": false
        },
        "ADMINUSLabs": {
            "result": "clean site",
            "detected": false
        },
        "Trustwave": {
            "result": "clean site",
            "detected": false
        },
        "Blueliv": {
            "result": "clean site",
            "detected": false
        },
        "Sophos": {
            "result": "unrated site",
            "detected": false
        },
        "Emsisoft": {
            "result": "clean site",
            "detected": false
        },
        "Phishtank": {
            "result": "clean site",
            "detected": false
        },
        "AegisLab WebGuard": {
            "result": "clean site",
            "detected": false
        },
        "ZDB Zeus": {
            "result": "clean site",
            "detected": false
        },
        "Malwared": {
            "result": "clean site",
            "detected": false
        },
        "Malekal": {
            "result": "clean site",
            "detected": false
        },
        "Malwarebytes hpHosts": {
            "result": "clean site",
            "detected": false
        },
        "zvelo": {
            "result": "clean site",
            "detected": false
        },
        "Malc0de Database": {
            "result": "clean site",
            "detail": "http://malc0de.com/database/index.php?search=www.virustotal.com",
            "detected": false
        },
        "MalwareDomainList": {
            "result": "clean site",
            "detail": "http://www.malwaredomainlist.com/mdl.php?search=www.virustotal.com",
            "detected": false
        },
        "MalwarePatrol": {
            "result": "clean site",
            "detected": false
        },
        "Spam404": {
            "result": "clean site",
            "detected": false
        },
        "ThreatHive": {
            "result": "clean site",
            "detected": false
        },
        "CLEAN MX": {
            "result": "clean site",
            "detected": false
        },
        "Sucuri SiteCheck": {
            "result": "clean site",
            "detected": false
        },
        "Virusdie External Site Scan": {
            "result": "clean site",
            "detected": false
        },
        "Quttera": {
            "result": "clean site",
            "detected": false
        },
        "Spamhaus": {
            "result": "clean site",
            "detected": false
        },
        "CyberCrime": {
            "result": "clean site",
            "detected": false
        },
        "Nucleon": {
            "result": "clean site",
            "detected": false
        },
        "Fortinet": {
            "result": "clean site",
            "detected": false
        },
        "Zerofox": {
            "result": "clean site",
            "detected": false
        },
        "Google Safebrowsing": {
            "result": "clean site",
            "detected": false
        },
        "Rising": {
            "result": "clean site",
            "detected": false
        },
        "Web Security Guard": {
            "result": "clean site",
            "detected": false
        },
        "CyRadar": {
            "result": "clean site",
            "detected": false
        },
        "AutoShun": {
            "result": "unrated site",
            "detected": false
        },
        "FraudSense": {
            "result": "clean site",
            "detected": false
        },
        "Netcraft": {
            "result": "unrated site",
            "detected": false
        },
        "K7AntiVirus": {
            "result": "clean site",
            "detected": false
        },
        "malwares.com URL checker": {
            "result": "clean site",
            "detected": false
        },
        "Certly": {
            "result": "clean site",
            "detected": false
        },
        "AlienVault": {
            "result": "clean site",
            "detected": false
        },
        "BitDefender": {
            "result": "clean site",
            "detected": false
        },
        "SCUMWARE.org": {
            "result": "clean site",
            "detected": false
        },
        "Kaspersky": {
            "result": "clean site",
            "detected": false
        },
        "PhishLabs": {
            "result": "unrated site",
            "detected": false
        },
        "Opera": {
            "result": "clean site",
            "detected": false
        },
        "Malware Domain Blocklist": {
            "result": "clean site",
            "detected": false
        },
        "Avira": {
            "result": "clean site",
            "detected": false
        },
        "desenmascara.me": {
            "result": "clean site",
            "detected": false
        },
        "Webutation": {
            "result": "clean site",
            "detected": false
        },
        "StopBadware": {
            "result": "unrated site",
            "detected": false
        },
        "G-Data": {
            "result": "clean site",
            "detected": false
        },
        "FraudScore": {
            "result": "clean site",
            "detected": false
        },
        "Comodo Site Inspector": {
            "result": "clean site",
            "detected": false
        },
        "Yandex Safebrowsing": {
            "result": "clean site",
            "detail": "http://yandex.com/infected?l10n=en&url=https://www.virustotal.com/vtapi/v2/url/report",
            "detected": false
        }
    }
}
IOC Review Completed!
````
