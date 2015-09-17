import json
import glob

import kpc
import read_iptables
import api
import create_policy


# Get Iptables
#files = zip((glob.glob("*.iptables")), (glob.glob("*.saves")))
files = glob.glob("*.saves")
ports_file = open("test.ports", 'r')

portlist = kpc.read_ports(ports_file)

for s in files:
    print "START" + s
    mylist_input_final, mylist_output_final, save_forward = read_iptables.read_IptableSave(s)

    existing_IP = kpc.existing_IPzone(api.get_IPzones())
    existing_Service = kpc.existing_service(api.get_Services())
    existing_Interfaces = kpc.existing_interfaces(api.get_interfaces())
    existing_Group = kpc.existing_groups(api.get_Groups())

    zones,groups = kpc.create_IPzone(mylist_input_final, mylist_output_final, existing_IP, existing_Group)
    services = kpc.create_networkService(mylist_input_final,mylist_output_final,existing_Service, portlist)
    interfaces = kpc.create_networkInterface(mylist_input_final,mylist_output_final,existing_Interfaces)

    api.post_IPzones(zones)
    api.post_Groups(groups)
    api.post_Interfaces(interfaces)
    api.post_Services(services)

    Service_latest = api.latest_Service()
    IP_latest = api.latest_IP()
    Interface_latest = api.latest_Interface()
    Group_latest = api.latest_Groups()

    policies = create_policy.create_Policy(s, mylist_input_final, mylist_output_final, IP_latest, Service_latest, Interface_latest, Group_latest)

    api.post_firewallPolicy(policies)
