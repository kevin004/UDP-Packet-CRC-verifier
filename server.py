#!/usr/bin/env python
'''
UDP server class that uses threading to set up a socket, accepts command line arguments
and arguments to initialize class, otherwise uses default arguments. This server further
verifies incoming UDP packets through a cyclic redundancy check (CRC32).
'''

import sys, time, json, _thread as thread 
from socket import *
from struct import *

defKeys = {"0x42": "key.bin", "0x1337": "super_secret_key.bin"}
defBinaries = {"0x42": "cat.jpg", "0x1337": "kitten.jpg"}
defImg = 'cat.jpg'
host = ''
defPort = 1337
defDelay = 1

class UDPServer:
    #initialize class with defaults unless specified
    def __init__(
        self, keys=defKeys, binaries=defBinaries, 
        img=defImg, port=defPort, delay=defDelay
        ):
        self.keys = keys
        self.binaries = binaries
        self.img = img
        self.port = port 
        self.delay = delay
    
    #Main
    def handleClient(self, data):
        packet_ID, packet_seq, XOR_key, checksums, data_XOR, signature = self.parseUDP(data[0])

        #Parse image data for CRC check
        if (self.binaries[hex(packet_ID)]):
            self.img = self.binaries[hex(packet_ID)]
        try:
            img_file = open(self.img, 'rb')
            img_data = self.getImgData(img_file, packet_seq, checksums)
        except:
            print('No file called %s' % self.img)
        else:
        #CRC_XOR UDP and image
            packet_decode = self.decodeXOR(data_XOR, XOR_key)
            img_decode = self.decodeXOR(img_data, XOR_key)
            self.xor_Logger(checksums, packet_decode, img_decode, packet_ID, packet_seq)

    #Connect to socket and pass control to handleClient
    def dispatcher(self):
        self.parseCommandLine()
        with socket(AF_INET, SOCK_DGRAM) as sockobj:
            sockobj.bind((host, self.port))
            while True:
                data = sockobj.recvfrom(60000)
                print('Server connected by', data[1], end=' ')
                print('at', self.now())  
                print('address', data[1])
                thread.start_new_thread(self.handleClient, (data,))

    #Parse command line for keyword arguments
    def parseCommandLine(self):
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '--keys':
                self.keys = json.loads(sys.argv[i+1])
            if sys.argv[i] == '--binaries':
                self.binaries = json.loads(sys.argv[i+1])
            if sys.argv[i] == '-d':
                self.delay = int(sys.argv[i+1])
            if sys.argv[i] == '-p':
                self.port = int(sys.argv[i+1])

    #Parse custom UDP packet and return values as tuple
    def parseUDP(self, data):
        header_length = 12

        #Parse header
        udp_header = data[: header_length]
        udp_header = unpack('!LIHH', udp_header)
        packet_id = udp_header[0]
        packet_seq = udp_header[1]
        XOR_key = udp_header[2]
        checksums = udp_header[3]
        XOR_key_bin = bin(int(XOR_key))

        #Parse data and signature
        data_length = checksums * 2
        XOR_cyclic = data[header_length: header_length + data_length]
        XOR_cyclic = unpack_from('!H', XOR_cyclic, offset=0)[0]
        data_XOR = bin(int(XOR_cyclic))
        signature = data[-64:]

        #Package tuple to return parsed data
        udp_data = (packet_id, packet_seq, XOR_key_bin, checksums, data_XOR, signature)
        return udp_data

    #Parse image data for XOR
    def getImgData(self, img_file, packet_seq, checksums):
        img_data = img_file.read()
        img_bytes = img_data[(packet_seq*2):((packet_seq+checksums)*2)]
        img_bytes = unpack_from('!H', img_bytes, offset=0)[0]
        img_bytes_bin = bin(int(img_bytes))
        return img_bytes_bin
    
    #return XOR
    def xor(self, a, b):
        res = []
        for i in range(1, len(b)):
            if a[i] == b[i]:
                res.append('0')
            else:
                res.append('1')
   
        return ''.join(res)

    #Mod-2-division
    def mod_division(self, num, divisor):
        choice = len(divisor)
        tmp = num[0 : choice]
   
        while choice < len(num):
            if tmp[0] == '1':
                tmp = self.xor(divisor, tmp) + num[choice]
            else:
                tmp = self.xor('0'*choice, tmp) + num[choice]
            choice += 1
        if tmp[0] == '1':
            tmp = self.xor(divisor, tmp)
        else:
            tmp = self.xor('0'*choice, tmp)
   
        return tmp

    #Cyclic redundancy check main function
    def decodeXOR(self, data, key):
        length = len(key)
        new_data = data + '0'*(length-1)
        remainder = self.mod_division(new_data, key)
        return remainder
    
    #Log CRC32 failed checks to file
    def xor_Logger(self, checksums, packet_data, img_data, packet_id, packet_seq):
        if packet_data != img_data:
            time.sleep(self.delay)
            f = open('checksum_failures.log', 'a')
            f.write(hex(packet_id) + '\n')
            f.write(str(packet_seq) + '\n')
            f.write(str(packet_seq+checksums) + '\n')
            f.write(hex(int(packet_data)) + '\n')
            f.write(hex(int(img_data)) + '\n')
            f.write('\n')

    #Return current time
    def now(self):
        return time.ctime(time.time())

if __name__ == '__main__':
    server = UDPServer()
    server.dispatcher()
