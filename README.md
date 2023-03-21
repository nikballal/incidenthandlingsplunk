# Incident Handling with Splunk using the Cyber Kill Chain Model

## Scenario

A website named http://www.imreallynotbatman.com (IP address - 192.168.250.70) owned by Wayne Enterprises has been defaced. The good thing is, that they have Splunk already in place, so we have got all the event logs related to the attacker's activities captured. We need to explore the records and find how the attacker got into their network and what actions they performed 

### Reconnaissance-

We will use query **'index=botsv1 imreallynotbatman.com'** to look for event logs in the index "botsv1" which contains the term 'imreallynotbatman.com'
and look for http traffic logs under **'stream:http'** log source. We determine the 40.80.148.42 to be source IP since it has generated large % of counts.

<img width="355" alt="2  src_ip" src="https://user-images.githubusercontent.com/89782464/226503432-74dd680f-06a1-4484-8977-56bc3807acda.PNG">

<img width="462" alt="1  sourcetypes" src="https://user-images.githubusercontent.com/89782464/226498320-00bc4bf8-42ae-44ea-a9ec-a0f53824c71c.PNG">

- validate the IP using the Search Query: index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
- checking the signature alerts from the suricata logs.


From the logs, under the 'request' field we are able to determine the CMS of our web-server - 'joomla', Acunetix as the web scanner

<img width="466" alt="cms" src="https://user-images.githubusercontent.com/89782464/226505227-e256b34b-2d8d-480a-921f-166aa9a62491.PNG">


<img width="293" alt="web scanner" src="https://user-images.githubusercontent.com/89782464/226505237-c3712e5c-c022-450f-a184-ba558e5ac35d.PNG">

### Exploitation
Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
Query Explanation: This query will look for all the inbound traffic towards IP 192.168.250.70.

To see what kind of traffic is coming through the POST requests, we will narrow down on the field http_method=POST as shown below:
Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST


We can narrow down our search to see the requests sent to the login portal using this information.

Search query: index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70"  uri="/joomla/administrator/index.php"



form_data The field contains the requests sent through the form on the admin panel page, which has a login page. We suspect the attacker may have tried multiple credentials in an attempt to gain access to the admin panel. To confirm, we will dig deep into the values contained within the form_data field, as shown below:
Query Explanation: We are going to add uri="/joomla/administrator/index.php" in the search query to show the traffic coming into this URI.

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
Query Explanation: We will add this -> | table _time uri src dest_ip form_data to create a table containing important fields as shown below:

If we keep looking at the results, we will find two interesting fields username that includes the single username admin in all the events and another field passwd that contains multiple passwords in it, which shows the attacker from the IP 23.22.63.114 Was trying to guess the password by brute-forcing and attempting numerous passwords


### Installation
In the previous Exploitation phase, we found evidence of the webserver iamreallynotbatman.com getting compromised via brute-force attack by the attacker using the python script to automate getting the correct password. The attacker used the IP" for the attack and the IP to log in to the server. This phase will investigate any payload / malicious program uploaded to the server from any attacker's IPs and installed into the compromised server.

- To begin an investigation, we first would narrow down any http traffic coming into our server 192.168.250.70 containing the term ".exe." This query may not lead to the findings, but it's good to start from 1 extension and move ahead.
- Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
