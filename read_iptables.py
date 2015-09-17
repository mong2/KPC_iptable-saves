import re
import json
import collections
import re
import glob


#read iptable-save file
def read_IptableSave(save_filename):
    final_input = []
    final_output = []
    save_forward = []
    text_file    = open(save_filename, 'r')

    for line in text_file:
        tokens = re.split(r"[' ']+", line)
        if "INPUT" in tokens:
            save_input   = []
            for i in range(len(tokens)):
                if tokens[i] == "-s":
                    save_input.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-p":
                    port = tokens[i+1].upper()
                elif tokens[i] == "--sport" or tokens[i] == "--dport":
                    save_input.append((tokens[i+1],port))
                elif tokens[i] == "--state":
                    save_input.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-j":
                    save_input.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-i":
                    save_input.append((tokens[i], tokens[i+1]))
            final_input.append(save_input)
        elif "OUTPUT" in tokens:
            save_output  = []
            for i in range(len(tokens)):
                if tokens[i] == "-d":
                    save_output.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-p":
                    port = tokens[i+1].upper()
                elif tokens[i] == "--sport" or tokens[i] == "--dport" :
                    save_output.append((tokens[i+1],port))
                elif tokens[i] == "--state":
                    save_output.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-j":
                    save_output.append((tokens[i],tokens[i+1]))
                elif tokens[i] == "-i":
                    save_output.append((tokens[i], tokens[i+1]))
            final_output.append(save_output)
        elif "FORWARD" in tokens:
            save_forward.append(line)

    return final_input, final_output, save_forward



#read the text file and generate input, output and chain for special cases
def read_Iptables(filename):
    mylist_input =[]
    mylist_output =[]
    chain = []
    exclude_forward = []
    text_file = open(filename, 'r')

    for line in text_file:
        tokens = re.split(r"[' ']+", line)
        print tokens
        if len(tokens) < 2:
            continue
        elif tokens[0] == "Chain":
            if tokens[1] == "INPUT":
                flag = 'i'
            elif tokens[1] == "FORWARD":
                flag = 'f'
                exclude_forward.append(line)
            elif tokens[1] == "OUTPUT":
                flag = 'o'
            else:
                chain.append(tokens[1])
                flag = ''
        elif tokens[1] == "pkts":
            continue
        elif tokens[3] != None:
            if flag == 'i':
                mylist_input.append(tokens)
            elif flag == 'f':
                exclude_forward.append(line)
                continue
            elif flag == 'o':
                mylist_output.append(tokens)
        if flag == 'x':
            print "flag=x.  something's wrong"
    return mylist_input, mylist_output,chain, exclude_forward

#finding the speical chain and collect all the firewall rules they have
def Find_special_chain(filename, chain):

    text_file = open(filename, 'r')
    printing = False
    chain_list = []
    name = None
    shash = {}

    for line in text_file:
        m = re.search(r"Chain (\w+)", line)

        if m:
            if m.groups(1)[0] in chain:
                name = m.groups(1)[0]
                printing = True
            else:
                printing = False
        if printing:
            if (("Chain" in line) or ("pkts" in line)):
                pass
            else:
                chain_list.append((name,line))

    for i in range(len(chain)):
        for k, v in chain_list:
            if k == chain[i]:
                shash.setdefault(k,[]).append(v)


    return shash

def merge_special_chain(mylist_input, mylist_output,shash):

    flag = False
    mylist_input_final = []
    mylist_output_final = []
    token_hash = {}


    # this is for special cases. for nested firewall chain
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            for key in shash.keys():
                if len(tokens) < 2:
                    continue
                elif tokens[3] == key:
                    shash[entry].extend(shash[tokens[3]])

    # tokenize each value in shash
    for entry in shash:
        for i in range(len(shash[entry])):
            tokens =  re.split(r"[' ']+", shash[entry][i])
            #print tokens
            token_hash.setdefault(entry,[]).append(tokens)

    #append spcial chain to mylist_input in order
    for i in range(len(mylist_input)):
        if ((mylist_input[i][3] != "ACCEPT") and (mylist_input[i][3] != "REJECT") and (mylist_input[i][3] != "LOG") and (mylist_input[i][3] != "DROP")):
            mylist_input_final.append(mylist_input[i])
            for value in token_hash[mylist_input[i][3]]:
                if len(value) < 2:
                    continue
                else:
                    value.append("comment:"+mylist_input[i][3])
                    mylist_input_final.append(value)
        else:
            mylist_input_final.append(mylist_input[i])

    #append special chain to mylist_output in order
    for i in range(len(mylist_output)):
        if mylist_output[i][3] != "ACCEPT" and mylist_output[i][3] != "REJECT" and mylist_output[i][3] != "LOG" and mylist_output[i][3] != "DROP":
            mylist_output_final.append(mylist_output[i])
            for value in token_hash[mylist_output[i][3]]:
                if len(value) < 2:
                    continue
                else:
                    value.append("comment:"+mylist_input[i][3])
                    mylist_output_final.append(value)
        else:
            mylist_output_final.append(mylist_output[i])


    return mylist_output_final, mylist_input_final
