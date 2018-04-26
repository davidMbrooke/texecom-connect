#!/usr/bin/env python
#
# Decoder for Texecom Connect API/Protocol
#
# Copyright (C) 2018 Joseph Heenan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import socket
import time
import os

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
    
    def __init__(self, host, port , message_handler_func):
        self.host = host
        self.port = port
        self.crc8_func = crcmod.mkCrcFun(poly=0x185, rev=False, initCrc=0xff)
        self.nextseq = 0
        self.message_handler_func = message_handler_func
        self.print_network_traffic = True

    def hexstr(self,s):
        return " ".join("{:02x}".format(ord(c)) for c in s)

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))
        # if we send the login message to fast the panel ignores it; texecom
        # recommend 500ms, see:
        # http://texecom.websitetoolbox.com/post/show_single_post?pid=1303528828&postcount=4&forum=627911
        time.sleep(0.5)
        
    def getnextseq(self):
        if self.nextseq == 256:
            self.nextseq = 0
        next=self.nextseq
        self.nextseq += 1
        return next

    
    def recvresponse(self):
        """Receive a response to a command. Automatically handles any
        messages that arrive first"""
        while True:
            header = self.s.recv(self.LENGTH_HEADER)
            if self.print_network_traffic:
                print("Received message header:")
                hexdump.hexdump(header)
            msg_start,msg_type,msg_length,msg_sequence = list(header)
            payload = self.s.recv(ord(msg_length) - self.LENGTH_HEADER)
            if self.print_network_traffic:
                print("Received message payload:")
                hexdump.hexdump(payload)
            payload, msg_crc = payload[:-1], ord(payload[-1])
            expected_crc = self.crc8_func(header+payload)
            if msg_start != 't':
                print("unexpected msg start: "+hex(ord(msg_start)))
                return None
            if msg_crc != expected_crc:
                print("crc: expected="+str(expected_crc)+" actual="+str(msg_crc))
                return None
            # FIXME: check seq
            # FIXME: check we received the full expected length
            # FIXME: add a timeout to recv(), if panel takes over 1second to finish sending something is probably wrong
            if msg_type == self.HEADER_TYPE_COMMAND:
                print("received command unexpectedly")
                return None
            elif msg_type == self.HEADER_TYPE_RESPONSE:
                return payload
            elif msg_type == self.HEADER_TYPE_MESSAGE:
                self.message_handler_func(payload)
    
    def sendcommand(self, body):
        data = self.HEADER_START+self.HEADER_TYPE_COMMAND+chr(len(body)+5)+chr(self.getnextseq())+body
        data += chr(self.crc8_func(data))
        if self.print_network_traffic:
            print("Sending command:")
            hexdump.hexdump(data)
        self.s.send(data)
        
    def login(self, udl):
        body = self.CMD_LOGIN+udl
        self.sendcommand(body)
        payload=self.recvresponse()
        if payload == None:
            print("Invalid response to login command; try again.")
            return False
        print("login response payload is: "+self.hexstr(payload))
        commandid,response = list(payload)
        if commandid != self.CMD_LOGIN:
            print("Got response for wrong command id: "+hex(ord(commandid)))
            return False
        if response == self.CMD_RESPONSE_NAK:
            print("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            print("unexpected ack payload: "+hex(ord(response)))
            return False
        return True

    def set_event_messages(self):
        # this enables all messages
        body = self.CMD_SETEVENTMESSAGES+chr(0x3e)+chr(0x00)
        self.sendcommand(body)
        payload=self.recvresponse()
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
        payload=self.recvresponse()
        commandid,datetime = payload[0],payload[1:]
        if commandid != self.CMD_GETDATETIME:
            print("GETDATETIME got response for wrong command id: Expected "+hex(ord(self.CMD_GETDATETIME))+", got "+hex(ord(commandid)))
            print("Payload: "+self.hexstr(payload))
            return None
        if len(datetime) < 6:
            print("GETDATETIME: response too short")
            print("Payload: "+self.hexstr(payload))
            return None
        datetime = bytearray(datetime)
        datetimestr = '20{2:02d}/{1:02d}/{0:02d} {3:02d}:{4:02d}:{5:02d}'.format(*datetime)
        print("Panel date/time: "+datetimestr)
        return datetimestr

    def event_loop(self):
        while True:
            try:
                payload = tc.recvresponse()
        
            except socket.timeout:
                # send any message to reset the panel's 60 second timeout
                result = tc.get_date_time()
                if result == None:
                    print("Failure of 'get date time' is usually unrecoverable; exiting")
                    print("This may be due to a monitor only latch key; see http://texecom.websitetoolbox.com/post?id=9678400&trail=30")
                    # TODO could just reconnect
                    sys.exit(1)

    def debug_print_message(self, payload):
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

def message_handler(payload):
    tc.debug_print_message(payload)
    msg_type,payload = payload[0],payload[1:]
    if msg_type == tc.MSG_ZONEEVENT:
        zone_number = ord(payload[0])
        zone_bitmap = ord(payload[1])
        zone_state = zone_bitmap & 0x3
        if zone_number == 73 and zone_state == 1:
            print("Garage PIR activated; running script")
            os.system("./garage-pir.sh")

if __name__ == '__main__':
    texhost = '192.168.1.9'
    port = 10001
    udlpassword = '1234'
    tc = TexecomConnect(texhost, port, message_handler)
    tc.connect()
    if not tc.login(udlpassword):
        print("Login failed - udl password incorrect or pre-v4 panel, exiting.")
        sys.exit(1)
    print("login successful")
    tc.set_event_messages()
    tc.get_date_time()
    tc.s.settimeout(30)
    tc.event_loop()
