import re
ports_file = open("test.ports", 'r')


def read_ports(filename):
    myports = []
    for line in ports_file:
        tokens = re.split(r"[' ']+", line)
        myports.append((tokens[0], tokens[1]))
    return myports

portlists=read_ports(ports_file)


for element in portlists:
    print "G"
    if "tcp" in element[1]:
        print "TE"
