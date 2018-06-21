# firebase
Exploiting misconfigured [Firebase](https://firebase.google.com/) databases

## Disclaimer: The provided software is meant for educational purposes only. Use this at your own discretion, the creator cannot be held responsible for any damages caused. Please, use responsibly.

### Prerequisites
Non-standard python modules:
* [dnsdumpster](https://github.com/PaulSec/API-dnsdumpster.com)
* [bs4](http://beautiful-soup-4.readthedocs.io/en/latest/)
* [requests](https://github.com/requests/requests)

### Usage
```
python3 firebase.py
```
It will create a json file containing the gathered vulnerable databases and their dumped contents. Each database has a status:
* -1: means it's not vulnerable
* 0: further explotation may be possible
* 1: vulnerable

For a better results head to [pentest-tools.com](https://pentest-tools.com/information-gathering/find-subdomains-of-domain) and in its subdomain scanner introduce the following domain: ```firebaseio.com```. Once the scan has finished, save the page HTML(CRL+S) in the same directory as the script and name it: ```subdomains.html```. This will allow the script to analyze more subdomains. Further subdomain crawlers might get supported.

### Credits

This script is heavily based in the work by the Mobile Threat Team from [appthority](https://www.appthority.com/mobile-threat-center/blog/appthority-discovers-thousands-of-apps-with-firebase-vulnerability-exposing-sensitive-data/). All credits for the reasearch belong to them.
