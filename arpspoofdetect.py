# Use python2

import time
import socket
import struct
import random
import argparse
import sys
import csv
from netaddr import *
import binascii
import os
from threading import *

description = """
    ArpSpoffDetect is icmp echo implemations
    Usage: python arpspoofdetect.py --target  [ Options ...]
    Eg: python arpspoofdetect.py -t 192.168.2.0/24

"""

parser = argparse.ArgumentParser("Echo Request ICMP==Ping", description)
parser.add_argument("--target", "-t", help="target Host", required=True)
parser.add_argument("--wait", "-w", help="timeout  for waiting respose,Default 2 seconds", required=False, default=2)
parser.add_argument("--message", "-m", help="message in echo Request,default:rangers lead the way", required=False,
                    default='rangers lead the way')
parser.add_argument("--repetiton", "-r", help="Number of repetitions,default=3 ", required=False, default=3)

# Globals#
args = parser.parse_args()
ipToMacFrcmp = {}
ICMP_ECHO_REQUEST = 8
duplicateMac = {}
arpTable = {}


# LockOuput=None


# Globals#


##ParserMethods##
def hextoMac(raw):
    length = len(raw)
    index = 0
    mac = ''
    while index < length:
        mac = mac + ":" + raw[index:index + 2]
        index += 2
    return mac[1:]


def hextoIp(raw):
    length = len(raw)
    index = 0
    ip = ''
    while index < length:
        # print str(int(raw[index:index+2],16))
        ip = ip + "." + str(int(raw[index:index + 2], 16))
        index += 2
    return ip[1:]


##ParsersMethods##



##Listen IcmpReply##
def listIcmpReply():
    global ipToMacFrcmp
    # global  LockOuput
    time.sleep(2)
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    while True:
        packet, addr = rawSocket.recvfrom(1024)
        # print packet
        ethernet_header = packet[0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
        ipheader = packet[26:34]
        ip_detailed = struct.unpack("!4s4s", ipheader)

        try:
            header = packet[20:28]  # Icmp region
            p_type, code, checksum, id, sequence = struct.unpack('bbHHh', header)
            if p_type != 0 or code != 0:
                continue
        except Exception:
            pass

        destmac = hextoMac(binascii.hexlify(ethernet_detailed[0]))
        sourcemac = hextoMac(binascii.hexlify(ethernet_detailed[1]))
        destIp = hextoIp(binascii.hexlify(ip_detailed[1]))
        sourceIp = hextoIp(binascii.hexlify(ip_detailed[0]))

        ipToMacFrcmp[str(sourcemac)] = sourceIp

        ##LockOuput.acquire()
        print "------------FromIcmp-----------------"
        for key, value in ipToMacFrcmp.items():
            print key, "->", value
        print "------------FromIcmp-----------------"
        ##LockOuput.release()


###Check ArpTable





def getArpTable():
    with open('/proc/net/arp') as arpt:
        names = [
            'IP address', 'HW type', 'Flags', 'HW address',
            'Mask', 'Device'
        ]  # arp 1.88, net-tools 1.60

        reader = csv.DictReader(
            arpt, fieldnames=names,
            skipinitialspace=True,
            delimiter=' ')

        # Skip header.

        return [block for block in reader]


def clearArp(ip):
    os.system("arp -d " + str(ip) + " &> /dev/null")


def CheckArpTable(flag):
    global arpTable
    global duplicateMac

    table = getArpTable()

    for item in table[1:]:

        ip = item['IP address']
        mac = item['HW address']
        if flag:
            clearArp(ip)

        if str(mac) == "ff:ff:ff:ff:ff:ff" or str(mac) == "<incomplete>" or str(mac) == "incomplete" or str(
                mac) == '00:00:00:00:00:00':
            continue
        elif mac not in arpTable:
            pass
        elif ip != arpTable[mac]:
            # Duplicate Mac adress
            # print "Duplicate mac addres"
            # print arpTable[str(mac)], "->", mac
            # print ip, "->", mac
            # print "----------------------"
            duplicateMac[ip] = mac
            duplicateMac[arpTable[mac]] = mac
        arpTable[str(mac)] = ip
    print "-----------ArpTable-----------"
    for key, value in arpTable.items():
        print key, "->", value

        # clearArp(value)
    print "------------------------------"

    if flag:
        return
    elif len(duplicateMac) == 0:
        print "---No dublicate in my arp table,No spoffing to me---"
    else:

        print "-----------!!Poising!!-----------"
        for key, value in duplicateMac.items():
            print key, "->", value
        print "---------------------------------"


        # clearArp(key)


###------------


###------------

def checkSum(header):
    sum = 0
    size = len(header)
    # print size
    # for i in header:
    #    print ord(i)
    count = 0

    while count < size:
        this_val = ord(header[count + 1]) * 256 + ord(header[count])
        sum = sum + this_val
        count = count + 2
    if count < size:
        sum = sum + ord(header[len(header) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def generateIcmpPacket(id, message, sequence):
    """
    type 8->echo request,code ->0

    struct is equilivent  C language  struct
        in  struct format chracter
            ->b signed char
            ->H unsigned short
            ->h signed short
    ->Checksum is very important,if it  is not  match other fields which used calculating checksum value,host don't responds,I have tried
        ->Host dont' respond
        ->  in the below slide,there is good source to understand icmp and checksum and how to calculate
            https://www.scribd.com/doc/7074846/ICMP-and-Checksum-Calc

      0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type(8)   |     Code(0)   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Payload->Message->Data                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



   :
    """

    values = (8, 0, 0, id, sequence)
    s = struct.Struct('bbHHH')
    packet = s.pack(*values)

    my_checksum = checkSum(packet + message)

    # socket.htons ->Byte Ordering
    packet = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), id, sequence)
    return packet + message;


def send_ping(args, target, increment):
    """
    addres family->socket.AF_INET(ipv4)
    protocol->socket.getprotobyname("icmp")
    Raw socket->In more simple terms its for adding custom headers instead of headers provided by the underlying operating system.

    """
    icmpsocket = None
    try:
        icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error, msg:
        print 'Error : ' + str(msg[1])
        exit()

    host = None
    try:
        host = socket.gethostbyname(target)
    except Exception, e:
        print 'Erorr host: ' + str(e)
        exit()

    id = int((time.time() * random.random()) % 65535)  # because id field lenght is 16 bit
    # LockOuput.acquire()
    print "---------------------------ICMP Echo-------------------------------"
    print "Sended to " + host + " id=" + str(id) + " seqnum= " + str(42 + increment)
    print "-------------------------------------------------------------------"
    # LockOuput.release()
    packet = generateIcmpPacket(id, args.message, 42 + increment)

    while True:
        sent = icmpsocket.sendto(packet, (
            host, 42))  # There is no port for icmp message ,therefore we check incoming message id with our's sent id
        if (sent != 0):
            break;

    value = get_response(icmpsocket, id, time.time(), args)
    if (value == -1):
        print "Timeout to from " + host
    icmpsocket.close()


def get_response(icmpsocket, packet_id, timeofsent, args):
    # global LockOuput
    icmpsocket.settimeout(float(args.wait))

    try:
        while True:
            timeofreceive = time.time()
            response, addr = icmpsocket.recvfrom(1024)

            header = response[20:28]  # Icmp region

            p_type, code, checksum, id, sequence = struct.unpack('bbHHh', header)
            # print "Reply from "+str(addr[0]) +"  "+str(p_type)+"  "+ str(code)  +" " + str(checksum) + " "+"id= " + str(id) +  " ","seq=:"+str(sequence) +" len(response)"+ str(len(response))+ "in bytes"

            if id == packet_id:  # check id for this response belongs my requeust
                difference = timeofreceive - timeofsent
                # LockOuput.acquire()
                print "---------------------------ICMP REPLY-------------------------------"
                print "Reply from " + str(addr[0]) + " " + \
                      "id= " + str(id) + " " + \
                      "seq= " + str(sequence) + " " + \
                      "Response " + str(len(response)) + " in bytes" + " " + \
                      "message:" + response[28:] + " " + \
                      "time= " + str(round(difference * 1000.0, 4)) + " milliseconds"
                print "-------------------------------------------------------------------"
                # LockOuput.release()

            return 0

    except socket.timeout as errr:
        return -1


def getMacIpfromIcmp():
    global args
    while True:
        try:
            time.sleep(10)
            repetation = int(args.repetiton)
            count = 0;
            if ("/" in args.target):  # subnet

                for ip in IPSet([IPNetwork(args.target)]):
                    if count == 0 or count == 255:
                        pass;

                    else:
                        for i in range(0, repetation):
                            send_ping(args, str(ip), i)
                    count += 1;

            else:
                for i in range(0, repetation):
                    send_ping(args, args.target, i)

        except Exception as e: print str(e)



if __name__ == '__main__':
    # global LockOuput
    global arpTable
    global duplicateMac
    if len(sys.argv) < 2:
        print parser.print_help()
        exit()
    CheckArpTable(1)
    ##LockOuput = Lock()
    ##LockOuput.release()


    # t = Thread(target=listIcmpReply, args=())
    # t.start()
    t = Thread(target=getMacIpfromIcmp, args=())
    t.start()

    # main_thread = Thread.currentThread()

    count = 300;
    while True:
        CheckArpTable(0)
        arpTable = {}
        duplicateMac = {}
        time.sleep(1)
        if (count == 0):
            os.system("ip link set arp off dev eth0")
            os.system("ip link set arp on dev eth0")
            count=300
        else:
            count=count-1












