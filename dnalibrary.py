'''
Class sample for DNA center 
Purpose is DEVASC preparation training
'''

import requests
import urllib3
import warnings
import json
import time

class DnaC:
    '''
    DNA Center Class
    '''

    # Class variables (unhidden) to ease the creation of REST API calls
    AuthURL = "/dna/system/api/v1/auth/token"
    DeviceListURL = "/dna/intent/api/v1/network-device"
    HostListURL = "/api/v1/host"
    PathTraceURL = "/dna/intent/api/v1/flow-analysis"


    def __init__(self,url,port=443):
        '''
        Initialize a DNA Center Class
        --> requires a valid base URL
        verify if protocol in use in the url is https://
        append the port number in case non-standard port is used
        '''
        if url[:8] == "https://":
            self.baseURL = url
        else:
            self.baseURL = "https://" + url
        if port == 443:
            self.basePort = port
        else:
            self.baseURL += (":" + str(port))
        self.SSLverify = True
        self.Token = ""

    def disableSSLcheck(self):
        '''
        Disable TLS certificate validity check
        SSLverify object variable is used in all requests call
        '''
        urllib3.disable_warnings()
        self.SSLverify = False

    def enableSSLcheck(self):
        '''
        Enable Certificate validity check
        SSLverify object variable is used in all requests call
        '''
        warnings.resetwarnings()
        self.SSLverify = True


    def connect(self,username,password):
        '''
        Connect to DNA Center with basic authentication
        and store in the Token object variable the authentication Token
        '''

        # Headers are needed at least with Content-Type
        headers = {
                "Content-Type":"application/json"
                }

        # Credentials can be passed as tuple with username and password
        credentials = (username,password)

        # Retrieve the response of the authentication request, we are building the url as an f-string
        response = requests.post(f"{self.baseURL}{DnaC.AuthURL}",auth=credentials,headers=headers,verify=self.SSLverify)
        
        # parse the response as JSON and of the resulting dictionary, retrieve the value of "Token" key
        self.Token = response.json()["Token"]

    def hostlist(self,hostIp="",hostMac="",connectedNetworkDeviceName=""):
        '''
        Retrieve a list of hosts in DNA Center or a single host based on the parameters:
        host IP
        host MAC address
        Network device Name interconnected to
        '''

        # No more basic authentication needed with DNAC
        # we use the Token saved at connect time right as a header parameter (X-Auth-Token)
        # token is stored as an object variable
        headers = {
                "Content-Type":"application/json",
                "X-Auth-Token":self.Token
                }

        # Let's contruct the final URL for the list of hosts
        url = f"{self.baseURL}{DnaC.HostListURL}"

        # Allow for different query options (many more available!)
        # since I could not attach multiple query options together I set a priority on them in case
        # multiple are passed along, in that case hostIp>hostMac>connectedNetworkDeviceName
        if hostIp:
            url = f"{url}?hostIp={hostIp}"
        else:
            if hostMac:
                url = f"{url}?hostMac={hostMac}"
            else:
                if connectedNetworkDeviceName:
                    url = f"{url}?connectedNetworkDeviceName={connectedNetworkDeviceName}"
        
        # retrieve and return the response of the query
        response = requests.get(url,headers=headers,verify=self.SSLverify)
        return response.json()["response"]

    def devicelist(self,hostname="",platformId="",managementIpAddress=""):
        '''
        Returns a list of network devices or a single entry based on the parameters
        hostname
        platform ID
        management IP address
        '''
        headers = {
                "Content-Type":"application/json",
                "X-Auth-Token":self.Token
                }
        url = f"{self.baseURL}{DnaC.DeviceListURL}"
        if hostname:
            url = f"{url}?hostname={hostname}"
        else:
            if platformId:
                url = f"{url}?platformId={platformId}"
            else:
                if managementIpAddress:
                    url = f"{url}?managementIpAddress={managementIpAddress}"
        response = requests.get(url,headers=headers,verify=self.SSLverify)
        return response.json()["response"]

    def pathtrace(self,srcIP,dstIP):
        '''
        Execute and print a Path Trace between two IP addresses
        returns the status of the request (COMPLETED / FAILED)
        and DELETES the Path Trace from DNA center at the end
        '''

        # No more basic authentication needed with DNAC
        # we use the Token saved at connect time right as a header parameter (X-Auth-Token)
        # token is stored as an object variable
        headers = {
                "Content-Type":"application/json",
                "X-Auth-Token":self.Token
                }
        
        # This is the body of the request in dict() format
        # this dictionary can be passed directly as JSON data into the requests POST call
        # This method is much less prone to formatting errors since we are threading with
        # structured data
        body = {
                "sourceIP": srcIP,
                "destIP": dstIP,
                "inclusions": [
                    "INTERFACE-STATS",
                    "DEVICE-STATS",
                    "ACL-TRACE",
                    "QOS-STATS"
                    ],
                "protocol": "icmp"
                }

        # Let's build the final URL for the path trace request
        url = f"{self.baseURL}{DnaC.PathTraceURL}"
    
        # response_new store the response of the creation of a new Path Trace
        response_new = requests.post(url,headers=headers,json=body,verify=self.SSLverify)
        
        # We need to retrieve the flow_Analysis_Id from the new Path Trace creation request
        # for further processing, it is the key for all subsequent requests (status and delete)
        flow_analysis_id = response_new.json()["response"]["flowAnalysisId"]

        # Start a loop to poll DNAC and query the status of the Path Trace
        while True:
            # save the full response data into response_result
            response_result = requests.get(f"{url}/{flow_analysis_id}",headers=headers,verify=self.SSLverify)
            # save the status of the Path Trace into "status" variable
            status = response_result.json()["response"]["request"]["status"] 
            # in case the Path Trace has finished the elaboration (in any outcome), break the loop
            if status != "INPROGRESS":
                break
            # meanwhile the loop goes on inform about the status of the Path Trace
            print(f"Path Trace STATUS: {status}")
            # wait 5 seconds before the next poll
            time.sleep(5)
        
        # Elaborate and print the Path Trace data in case it did not fail
        if status != "FAILED":
            # Extract the list of the network devices in the Trace from the response
            networkElements = response_result.json()["response"]["networkElementsInfo"]
            # First Entry is written separately as the structure is different than the rest of the list
            print(f"{networkElements[0]['ip']}",end='->\n')
            # Loop through the list of network elements (from the second item)
            for networkElement in networkElements[1:]:
                # retrieve which interface was the inbound and which outbound of the trace on a network device
                # NOTE1: we use the .get() method to retrieve dictionary attributes because in case the structure
                # of some elements is different we can avoid to raise an exception
                # NOTE2: for NESTED dictionary attributes the .get() method needs to return at each parent attribute
                # an empty dictionary "{}" in case the attribute is missing, this way subsequent .get() method can be
                # still applicable and will not fail. Only last item needs to return the text we want to expose in case
                # of missing attributes (in this case "N/A")
                ifc_in = networkElement.get("ingressInterface",{}).get("physicalInterface",{}).get("name","N/A")
                ifc_out = networkElement.get("egressInterface",{}).get("physicalInterface",{}).get("name","N/A")
                device_name = networkElement["name"]
                # Some devices out of DNAC can be part of the trace, if so instead of showing an unknown name
                # we show their IP address (that is always known)
                if "unknown" in device_name.lower():
                    device_name = networkElement['ip']
                # Print the information about the Trace hop
                print(f"{ifc_in}-|{device_name}|-{ifc_out}",end='->\n')
            # as for the first element, the last element of the list has a different structure
            print(f"{networkElements[-1]['ip']}")
        else:
            # if the status is FAILED then just inform the user
            print("Path Trace STATUS: {status}")

        # Process a DELETE request for the Path Trace flow, so to not pollute the DNA Center
        response_delete = requests.delete(f"{url}/{flow_analysis_id}",headers=headers,verify=self.SSLverify)

        return status



if __name__ == '__main__':
    # This script can be also used as a library, in case is run as standalone 
    # issue some tests
    dna = DnaC("sandboxdnac.cisco.com")
    print(f"{'BaseURL:':15} {dna.baseURL:<45}")
    print(f"{'AuthURL:':15} {dna.AuthURL:<45}")
    print(f"{'DeviceListURL:':15} {dna.DeviceListURL:<45}")
    print(f"{'HostListURL:':15} {dna.HostListURL:<45}")
    print(f"{'PathTraceURL:':15} {dna.PathTraceURL:<45}")
    dna.disableSSLcheck()
    print(f"{'SSLverify:':15} {dna.SSLverify:<45}")
    dna.enableSSLcheck()
    print(f"{'SSLverify:':15} {dna.SSLverify:<45}")
    dna.connect("devnetuser","Cisco123!")
    print(f"{'Token:':15} {dna.Token:<45}")
    print(f"{'Full Host list:':15}"'\n'f"{json.dumps(dna.hostlist(),indent=2)}")
    print(f"{'Only Host MAC:c8:4c:75:68:b2:c0':15}"'\n'f"{json.dumps(dna.hostlist(hostMac='c8:4c:75:68:b2:c0'),indent=2)}")
    print(f"{'Only Host to cat_9k_2.abc.inc':15}"'\n'f"{json.dumps(dna.hostlist(connectedNetworkDeviceName='cat_9k_2.abc.inc'),indent=2)}")
    print(f"{'Full Device list:':15}"'\n'f"{json.dumps(dna.devicelist(),indent=2)}")
    dna.pathtrace("10.10.22.98","8.8.8.8")

