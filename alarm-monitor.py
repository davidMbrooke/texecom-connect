#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import socket
import time

import crcmod
import hexdump


class TexecomConnect:
    LENGTH_HEADER = 4
    HEADER_START = 't'
    HEADER_TYPE_COMMAND = 'C'
    HEADER_TYPE_RESPONSE = 'R'
    HEADER_TYPE_MESSAGE = 'M' # unsolicited message
    
    CMD_LOGIN = chr(1)
    CMD_GETDATETIME = chr(23)
    CMD_SETEVENTMESSAGES = chr(37)
    
    CMD_RESPONSE_ACK = '\x06'
    CMD_RESPONSE_NAK = '\x15'
    
    MSG_DEBUG = chr(0)
    MSG_ZONEEVENT = chr(1)
    MSG_AREAEVENT = chr(2)
    MSG_OUTPUTEVENT = chr(3)
    MSG_USEREVENT = chr(4)
    MSG_LOGEVENT = chr(5)
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.crc8_func = crcmod.mkCrcFun(poly=0x185, rev=False, initCrc=0xff)
        self.nextseq = 0

    def hexstr(self,s):
        return " ".join("{:02x}".format(ord(c)) for c in s)

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.s.connect((self.host, self.port))
        time.sleep(0.4)
        
    def getnextseq(self):
        if self.nextseq == 256:
            self.nextseq = 0
        next=self.nextseq
        self.nextseq += 1
        return next
    
    def recvpacket(self):
        header = self.s.recv(self.LENGTH_HEADER)
        #hexdump.hexdump(header)
        msg_start,msg_type,msg_length,msg_sequence = list(header)
        payload = self.s.recv(ord(msg_length) - self.LENGTH_HEADER)
        payload, msg_crc = payload[:-1], ord(payload[-1])
        expected_crc = self.crc8_func(header+payload)
        if msg_start != 't':
            print("unexpected msg start: "+hex(ord(msg_start)))
        # FIXME: check seq
        # FIXME: should probably make sure this isn't an 'M' message
        # FIXME: check we received the full expected length
        # FIXME: add a timeout to recv(), if panel takes over 1second to finish sending something is probably wrong
        if msg_crc != expected_crc:
            print("crc: expected="+str(expected_crc)+" actual="+str(msg_crc))
        return payload
    
    def sendcommand(self, body):
        data = 'tC'+chr(len(body)+5)+chr(self.getnextseq())+body
        data += chr(self.crc8_func(data))
        # hexdump.hexdump(data)
        self.s.send(data)
        
    def login(self, udl):
        body = self.CMD_LOGIN+udl
        self.sendcommand(body)
        payload=self.recvpacket()
        print("login response payload is: "+self.hexstr(payload))
        commandid,response = list(payload)
        if commandid != self.CMD_LOGIN:
            print("Got response for wrong command id: "+hex(ord(commandid)))
        if response == self.CMD_RESPONSE_NAK:
            print("NAK response from panel")
        elif response != self.CMD_RESPONSE_ACK:
            print("unexpected ack payload: "+hex(ord(response)))

    def set_event_messages(self):
        # this enables all messages
        body = self.CMD_SETEVENTMESSAGES+chr(0xff)+chr(0xff)
        self.sendcommand(body)
        payload=self.recvpacket()
        print("set event messages response payload is: "+self.hexstr(payload))
        commandid,response = list(payload)
        if commandid != self.CMD_SETEVENTMESSAGES:
            print("Got response for wrong command id: "+hex(ord(commandid)))
        if response == self.CMD_RESPONSE_NAK:
            print("NAK response from panel")
        elif response != self.CMD_RESPONSE_ACK:
            print("unexpected ack payload: "+hex(ord(response)))

    def get_date_time(self):
        body = self.CMD_GETDATETIME
        self.sendcommand(body)
        payload=self.recvpacket()
        commandid,datetime = payload[0],payload[1:]
        if commandid != self.CMD_GETDATETIME:
            print("Got response for wrong command id: "+hex(ord(commandid)))
        datetime = bytearray(datetime)
        datetimestr = '20{2:02d}/{1:02d}/{0:02d} {3:02d}:{4:02d}:{5:02d}'.format(*datetime)
        print("Panel date/time: "+datetimestr)


if __name__ == '__main__':
    texhost = '192.168.1.9'
    port = 10001
    tc = TexecomConnect(texhost, port)
    tc.connect()
    tc.login('1234')
    print("login successful")
    tc.set_event_messages()
    tc.get_date_time()
    tc.s.settimeout(30)
    while True:
        try:
            # FIXME: instead of doing this, have a callback when an
            # unsolicited message is received - that way we can cope
            # with messages that arrive when we're awaiting a command
            # response
            payload = tc.recvpacket()
            msg_type,payload = payload[0],payload[1:]
            if msg_type == tc.MSG_DEBUG:
                print("Debug message: "+tc.hexstr(payload))
            elif msg_type == tc.MSG_ZONEEVENT:
                if len(payload) == 2:
                    zone_number = ord(payload[0])
                    zone_bitmap = ord(payload[1])
                elif len(payload) == 3:
                    zone_number = ord(payload[0])+(ord(payload[1])<<8)
                    zone_bitmap = ord(payload[2])
                else:
                    print("unknown payload length")
                zone_state = zone_bitmap & 0x3
                zone_str = ["secure","active","tamper","short"][zone_bitmap & 0x3]
                if zone_bitmap & (1 << 2):
                    zone_str += ", fault"
                if zone_bitmap & (1 << 3):
                    zone_str += ", failed test"
                if zone_bitmap & (1 << 4):
                    zone_str += ", alarmed"
                if zone_bitmap & (1 << 5):
                    zone_str += ", manual bypassed"
                if zone_bitmap & (1 << 6):
                    zone_str += ", auto bypassed"
                if zone_bitmap & (1 << 7):
                    zone_str += ", zone masked"
                print("Zone event message: zone "+str(zone_number)+": "+zone_str)
            elif msg_type == tc.MSG_AREAEVENT:
                area_number = ord(payload[0])
                area_state = ord(payload[1])
                area_state_str = ["disarmed", "in exit", "in entry", "armed", "part armed", "in alarm"][area_state]
                print("Area event message: area "+str(area_number)+" "+area_state_str)
            elif msg_type == tc.MSG_OUTPUTEVENT:
                output_location = ord(payload[0])
                output_state = ord(payload[1])
                print("Output event message: location {:d} now 0x{:02x}".
                  format(output_location, output_state))
            elif msg_type == tc.MSG_USEREVENT:
                user_number = ord(payload[0])
                user_state = ord(payload[1])
                user_state_str = ["code", "tag", "code+tag"][user_state]
                print("User event message: logon by user {:d} {}".
                  format(user_number, user_state_str))
            elif msg_type == tc.MSG_LOGEVENT:
                print("Log event message: "+tc.hexstr(payload))
            else:
                print("unknown message type "+str(ord(msg_type))+": "+tc.hexstr(payload))

        except socket.timeout:
            # send any message to reset the panel's 60 second timeout
            tc.get_date_time()
        
    
