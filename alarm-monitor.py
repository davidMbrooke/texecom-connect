#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import socket
import time

import crcmod
import hexdump


class TexecomConnect:
    MSG_LOGIN = '\x01'
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.nextseq = 0
    
    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.s.connect((self.host, self.port))
        time.sleep(1)
        
    def getnextseq(self):
        if self.nextseq == 256:
            self.nextseq = 0
        next=self.nextseq
        self.nextseq += 1
        return next
    
    def recvstuff(self):
        header = self.s.recv(4)
        hexdump.hexdump(header)
        header = self.s.recv(3)
        hexdump.hexdump(header)
    
    def sendcommand(self, body):
        data = b'tC'+chr(len(body)+5)+chr(self.getnextseq())+body
        crc8_func = crcmod.predefined.mkPredefinedCrcFun("crc-8")
        foo = crc8_func(data)
        foo = 0x34
        data += chr(foo)
        hexdump.hexdump(data)
        self.s.send(data)
        self.recvstuff()
        
    def login(self):
        udl = '1234'
        body = self.MSG_LOGIN+udl
        self.sendcommand(body)
        
if __name__ == '__main__':
    texhost = '192.168.1.9'
    port = 10001
    tc = TexecomConnect(texhost, port)
    tc.connect()
    tc.login()
    
    print("successful")
    
