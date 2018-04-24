# Empire-API-Automation

This is an example Empire script that leverages the Empire APIs.
The script will wait for systems to connect and will automatically:

1. bypass user access controls 
2. discover local DNS server
3. lateral move to DNS server by leveraging invoke_wmi
4. use Powershell to discover DNS Zones and records
5. look for AWS DNS entries for lateral movement and data exfiltration

More information and attack scenarios will follow.
