#!/usr/bin/python

# Import the required libraries.
import json
import nmap
import csv

# Define the function to display header.
def print_header():
    print("CyberSecurity_MiniProject: Port scanning with nmap") 
    print("Create by Kaisen Wu")

# Define the function to read information of servers and ports from json file, return all the info as a dictionary.
def read_conf():
    f = open('conf.json')
    confDict = json.load(f)
    f.close()
    return confDict

# Define the port scan function at meantime display the scan result at console. The function returns a list of the result.
def run_nmap(server_dict):
    hostStr=""
    hostList=server_dict["servers"]
    portStr=server_dict["ports"]
    csvList = []
    for i,v in enumerate(hostList):
        if i==0:
            hostStr = hostStr + v
        else:
            hostStr = hostStr + " " + v
    nm = nmap.PortScanner()
    nm.scan(hosts=hostStr, ports=portStr)
    for host in nm.all_hosts():
        print("Host {0} IP {1} status {2}".format(nm[host].hostname(),host,nm[host].state()))
        for proto in nm[host].all_protocols():
            portList = nm[host][proto].keys()
            for port in portList:
                print("\tPort {0} is {1}".format(port, nm[host][proto][port]['state']))
                csvList.append({"Server IP": host, "Port": port, "Status": nm[host][proto][port]['state']})
        print()
    return csvList

# Define the csv output function.
def writeCSV(csvList):
    with open('network_scanner_output.csv', 'w', newline='\n') as outFile:
        sDictWriter = csv.DictWriter(outFile, ['Server IP', 'Port', 'Status'])
        sDictWriter.writeheader()
        for row in csvList:
            sDictWriter.writerow(row)


# Call all functions.
print("-------------------------------------------------------")
print_header()
print("-------------------------------------------------------") 
confDict = read_conf()
writeCSV(run_nmap(confDict))