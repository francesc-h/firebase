# firebase
Exploiting vulnerable/misconfigured [Firebase](https://firebase.google.com/) databases

## Disclaimer: The provided software is meant for educational purposes only. Use this at your own discretion, the creator cannot be held responsible for any damages caused. Please, use responsibly!

### Prerequisites
Non-standard python modules:
* [dnsdumpster](https://github.com/PaulSec/API-dnsdumpster.com)
* [bs4](http://beautiful-soup-4.readthedocs.io/en/latest/)
* [requests](https://github.com/requests/requests)

### Usage
```
python3 firebase.py [-h] [--dnsdumpster] [-d /path/to/file.htm] [-f results.json] [-l /path/to/file] [-c 100] [-p 4]
```
Arguments:
```
    -h      Show the help message
    -d      Absolute path to the downloaded HTML file.
    -f      Output file name. Default: results.json
    -c      Crawl for domains in the top-1m by Alexa. Set how many domains to crawl, for example: 100. Up to 1000000
    -p      How many processes to execute. Default: 1
    -l      Path to a file containing the DBs to crawl. One DB name per line. This option can't be used with -d or -c
    --dnsdumpster       Use the DNSDumpster API to gather DBs
```

The script will create a json file containing the gathered vulnerable databases and their dumped contents. Each database has a status:
* -2: DB doesn't exists
* -1: means it's not vulnerable
*  0: further explotation may be possible
*  1: vulnerable

For a better results head to [pentest-tools.com](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) and in its subdomain scanner introduce the following domain: ```firebaseio.com```. Once the scan has finished, save the page HTML(CRL+S) and use the ```-d [path]``` argument, this will allow the script to analyze the subdomains discovered by that service. Further subdomain crawlers might get supported.

### Credits

This script is heavily based on the work by the Mobile Threat Team from [appthority](https://www.appthority.com/mobile-threat-center/blog/appthority-discovers-thousands-of-apps-with-firebase-vulnerability-exposing-sensitive-data/). All credits for the reasearch belong to them.

To download the domains from the Alexa's 1 million top domains file, the [script](https://gist.github.com/evilpacket/3628941) by @evilpacket is used.
