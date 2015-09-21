import json
import re
# Create list for existing ipzones
def existing_IPzone(jsondata):
    existing_IP ={}
    for entry in jsondata['firewall_zones']:
        existing_IP[entry['name']] = entry['ip_address']
    return existing_IP

# Create list for existing firewall services
def existing_service(jsondata):
    existing_Service = []
    for entry in jsondata['firewall_services']:
        existing_Service.append((entry['port'], entry['protocol']))
    return existing_Service

# Create list for existing firewall interfaces
def existing_interfaces(jsondata):
    existing_Interface = []
    for entry in jsondata['firewall_interfaces']:
        existing_Interface.append(entry['name'])
    return existing_Interface

# Create list for existing server groups
def existing_groups(jsondata):
    existing_Group = []
    for entry in jsondata['groups']:
        existing_Group.append(entry['name'])
    return existing_Group

# Read in .ports file.
def read_ports(ports_file):
    myports = []
    text_file  = open(ports_file, 'r')
    for line in text_file:
        tokens = re.split(r"[' ']+", line)
        myports.append((tokens[0], tokens[1]))

    return myports


# create_IPzone.
# we will need to check if the IPzone is in Halo already. If not we will need to create a new IPzone.
# Tricky part is how do we name the IPzone
def create_IPzone(mylist_input, mylist_output, existing_IP, existing_Group):
    zone = {}
    zone.setdefault('firewall_zone', [])
    group = []
    #print "EXXXXXXXXX"

    for list_input in mylist_input:
        for k, v in list_input:
            if k == "-s" :
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                    if v not in existing_IP.values():
                        dict1={'name': v, 'ip_address': v}
                        for i in zone.values():
                            if dict1 not in i:
                                zone['firewall_zone'].append(dict1)
                else:
                    if v not in existing_Group:
                        dict2={'name': v}
                        if dict2 not in group:
                            group.append(dict2)

    for list_output in mylist_output:
        for k, v in list_output:
            if k == "-d":
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                    if v not in existing_IP.values():
                        dict1={'name': v, 'ip_address': v}
                        for i in zone.values():
                            if dict1 not in i:
                                zone['firewall_zone'].append(dict1)
                else:
                    if v not in existing_Group:
                        dict2={'name': v}
                        if dict2 not in group:
                            group.append(dict2)
    return zone, group

# create network services
# if network service is not in Halo then we will need to create a new one
def create_networkService(mylist_input, mylist_output,existing_Service, portlist):
    service =[]
    service_count = 0
    service_create_in_input = []
    dict1 = None

    for list_input in mylist_input:
        for port, protocol in list_input:
            if protocol == "UDP" or protocol == "TCP" or protocol == "ICMP":
                if (port,protocol) not in existing_Service:
                    for element in portlist:
                        if port == element[0] and (protocol.lower() in element[1]):
                            name_portlist = re.sub('/.+$', '', element[1]).strip()
                            protocol_portlist = re.sub('^.+/', '', element[1]).strip()
                            if name_portlist == "-":
                                name_portlist = protocol_portlist + "/" + element[0]
                            dict1 = {'name': name_portlist, 'protocol': protocol_portlist, 'port': port}
                        elif port != element[0] and protocol.lower() not in element[1]:
                            dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                    if dict1 not in service and dict1 != None:
                        service.append(dict1)

    for list_output in mylist_output:
        for port, protocol in list_output:
            if protocol == "UDP" or protocol == "TCP" or protocol == "ICMP":
                if (port,protocol) not in existing_Service:
                    for element in portlist:
                        if port == element[0] and (protocol.lower() in element[1]):
                            name_portlist = re.sub('/.+$', '', element[1]).strip()
                            protocol_portlist = re.sub('^.+/', '', element[1]).strip()
                            if name_portlist == "-":
                                name_portlist = protocol_portlist + "/" + element[0]
                            dict1 = {'name': name_portlist, 'protocol': protocol_portlist, 'port': port}
                        elif port != element[0] and protocol.lower() not in element[1]:
                            dict1 = {'name': protocol + "/" + port, 'protocol': protocol.lower(), 'port': port}
                    if dict1 not in service and dict1 != None:
                        service.append(dict1)
    return service

# create network interfaces
# if network interface is not in Halo then we will need to create a new one.
def create_networkInterface(mylist_input,mylist_output,existing_Interfaces):
    interface = {}
    interface.setdefault('firewall_interface', [])
    for list_input in mylist_input:
        for k,v in list_input:
            if k == "-i" and v not in existing_Interfaces:
                dict1={'name': v}
                for i in interface.values():
                    if dict1 not in i:
                        interface['firewall_interface'].append(dict1)

    for list_output in mylist_input:
        for k,v in list_output:
            if k == "-i" and v not in existing_Interfaces:
                dict1={'name': v}
                for i in interface.values():
                    if dict1 not in i:
                        interface['firewall_interface'].append(dict1)
    print interface
    return interface
