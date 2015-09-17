import json
import re
from collections import OrderedDict


def create_Policy(filename, mylist_input,mylist_output,latest_IP, latest_Service, latest_Interface, latest_Groups):
    policy          = {}
    rule            = {}
    rule.setdefault('firewall_rules', [])

    #inbound rules
    for list_input in mylist_input:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None
        action          = None
        comment         = None
        source_type     = "FirewallZone"

        if '-s' not in (element[0] for element in list_input):
            for ip, ip_value in latest_IP:
                if ip == "any":
                    IP_id = ip_value

        for k,v in list_input:
            #define action
            if k == "-j":
                action = v.rstrip('\n')

            #define source
            if k == "-s":
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                    for ip, ip_value in latest_IP:
                        if v == ip:
                            IP_id = ip_value
                else:
                    for group, group_value in latest_Groups:
                        if v == group:
                            IP_id = group_value
                            source_type = "Group"

            #define interface
            for interface, interface_value in latest_Interface:
                if v == interface:
                    interface_id = interface_value

            #define service
            if v == "UDP" or v == "TCP" or v == "ICMP":
                service_name = v + "/" + k
                print service_name
            for service, service_value in latest_Service:
                if service_name == service:
                    Service_id = service_value

            #define state
            if k == "--state":
                states = v

        dict2 = {'chain'                : "INPUT",
                 'active'               : True,
                 'action'               : action,
                 'firewall_interface'   : interface_id,
                 'firewall_source'      : {'id': IP_id, "type": source_type},
                 'firewall_service'     : Service_id,
                 'connection_states'    : states,
                 'log'                  : log,
                 'comment'              : comment
                 }

        rule['firewall_rules'].append(dict2)
    print json.dumps(rule['firewall_rules'], indent =2)

    # #outbound rules
    for list_output in mylist_output:
        log             = False
        IP_id           = None
        Service_id      = None
        service_name    = None
        interface_id    = None
        states          = None
        action          = None
        comment         = None
        source_type     = "FirewallZone"

        print list_output


        if '-d' not in (element[0] for element in list_output):
            for ip, ip_value in latest_IP:
                if ip == "any":
                    IP_id = ip_value

        for k,v in list_output:
            #define action
            if k == "-j":
                action = v.rstrip('\n')

            #define source
            if k == "-d":
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                    for ip, ip_value in latest_IP:
                        if v == ip:
                            IP_id = ip_value
                else:
                    for group, group_value in latest_Groups:
                        if v == group:
                            IP_id = group_value
                            source_type = "Group"

            #define interface
            for interface, interface_value in latest_Interface:
                if v == interface:
                    interface_id = interface_value

            #define service
            if v == "UDP" or v == "TCP" or v == "ICMP":
                service_name = v + "/" + k
                print service_name
            for service, service_value in latest_Service:
                if service_name == service:
                    Service_id = service_value

            #define state
            if k == "--state":
                states = v

        dict2 = {'chain'                : "OUTPUT",
                 'active'               : True,
                 'action'               : action,
                 'firewall_interface'   : interface_id,
                 'firewall_target'      : {'id': IP_id, "type": source_type},
                 'firewall_service'     : Service_id,
                 'connection_states'    : states,
                 'log'                  : log,
                 'comment'              : comment
                 }
        print IP_id
        rule['firewall_rules'].append(dict2)

    dict1 = {'firewall_rules'   : rule['firewall_rules'],
             'platform'         : 'linux',
             'name'             : filename}

    policy = {'firewall_policy': dict1}

    print "<!-------POLICY--------->"
    return policy
