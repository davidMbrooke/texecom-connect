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
import datetime
import os
import sys
import re

import crcmod
import hexdump

class User(object):
    def __init__(self):
        self.passcode = None
        self.tag = None

    def valid(self):
        return self.passcode != '' or self.tag != ''


class Area(object):
    def __init__(self):
        pass


class Zone(object):
    """Information about a zone and it's current state
    """
    def __init__(self, zone_number):
        self.number = zone_number
        self.text = ""
        self.__active = False
        self.active_func = None
        self.active_since = None
        self.last_active = None
        self.__smoothed_active = False
        self.smoothed_active_delay = 30 # how long 'smoothed_active' will stay after last activation
        self.smoothed_active_func = None
        self.smoothed_active_since = None
        self.smoothed_last_active = None
        pass

    def update(self):
        if self.smoothed_active and not self.active:
            time_since_last_active = time.time() - self.last_active
            if time_since_last_active > self.smoothed_active_delay:
                self.smoothed_active = False
        if self.smoothed_active and self.smoothed_active_func is not None:
            # Run the handler on every update whilst 'smoothed active' is true
            self.smoothed_active_func(self, True, True)
        if self.active and self.active_func is not None:
            self.active_func(self, True, True)


    @property
    def smoothed_active(self):
        return self.__smoothed_active

    @smoothed_active.setter
    def smoothed_active(self, smoothed_active):
        if smoothed_active == self.__smoothed_active:
            return
        if self.smoothed_active_func is not None:
            self.smoothed_active_func(self, self.__smoothed_active, smoothed_active)
        self.__smoothed_active = smoothed_active
        if smoothed_active:
            self.smoothed_active_since = time.time()
        else:
            self.smoothed_active_since = None
            self.smoothed_last_active = time.time()


    @property
    def active(self):
        return self.__active

    @active.setter
    def active(self, active):
        if active == self.__active:
            return
        if self.active_func is not None:
            self.active_func(self, self.__active, active)
        self.__active = active
        if active:
            self.active_since = time.time()
            self.smoothed_active = True
        else:
            self.last_active = time.time()
            self.active_since = None

class TexecomConnect(object):
    LENGTH_HEADER = 4
    HEADER_START = 't'
    HEADER_TYPE_COMMAND = 'C'
    HEADER_TYPE_RESPONSE = 'R'
    HEADER_TYPE_MESSAGE = 'M'  # unsolicited message

    CMD_LOGIN = chr(1)
    CMD_GETZONEDETAILS = chr(3)
    CMD_GETLCDDISPLAY = chr(13)
    CMD_GETLOGPOINTER = chr(15)
    CMD_GETPANELIDENTIFICATION = chr(22)
    CMD_GETDATETIME = chr(23)
    CMD_GETSYSTEMPOWER = chr(25)
    CMD_GETUSER = chr(27)
    CMD_GETAREADETAILS = chr(35)
    CMD_SETEVENTMESSAGES = chr(37)

    # 2-3 seconds is mentioned in section 5.5 of protocol specification
    # Increasing this value is not recommended as it will mean if the
    # panel fails to respond to a command (as it sometimes does it it
    # sends an event at the same time we send a command) it will take
    # longer for us to realise and resend the command
    CMD_TIMEOUT = 2
    CMD_RETRIES = 3

    ZONETYPE_UNUSED = 0

    CMD_RESPONSE_ACK = '\x06'
    CMD_RESPONSE_NAK = '\x15'

    MSG_DEBUG = chr(0)
    MSG_ZONEEVENT = chr(1)
    MSG_AREAEVENT = chr(2)
    MSG_OUTPUTEVENT = chr(3)
    MSG_USEREVENT = chr(4)
    MSG_LOGEVENT = chr(5)

    zone_types = {}
    zone_types[1] = "Entry/Exit 1"
    zone_types[2] = "Entry/Exit 2"
    zone_types[3] = "Interior"
    zone_types[4] = "Perimeter"
    zone_types[5] = "24hr Audible"
    zone_types[6] = "24hr Silent"
    zone_types[7] = "Audible PA"
    zone_types[8] = "Silent PA"
    zone_types[9] = "Fire Alarm"
    zone_types[10] = "Medical"
    zone_types[11] = "24Hr Gas Alarm"
    zone_types[12] = "Auxiliary Alarm"
    zone_types[13] = "24hr Tamper Alarm"
    zone_types[14] = "Exit Terminator"
    zone_types[15] = "Keyswitch - Momentary"
    zone_types[16] = "Keyswitch - Latching"
    zone_types[17] = "Security Key"
    zone_types[18] = "Omit Key"
    zone_types[19] = "Custom Alarm"
    zone_types[20] = "Confirmed PA Audible"
    zone_types[21] = "Confirmed PA Audible"

    log_event_types = {}
    log_event_types[1] = "Entry/Exit 1"
    log_event_types[2] = "Entry/Exit 2"
    log_event_types[3] = "Interior"
    log_event_types[4] = "Perimeter"
    log_event_types[5] = "24hr Audible"
    log_event_types[6] = "24hr Silent"
    log_event_types[7] = "Audible PA"
    log_event_types[8] = "Silent PA"
    log_event_types[9] = "Fire Alarm"
    log_event_types[10] = "Medical"
    log_event_types[11] = "24Hr Gas Alarm"
    log_event_types[12] = "Auxiliary Alarm"
    log_event_types[13] = "24hr Tamper Alarm"
    log_event_types[14] = "Exit Terminator"
    log_event_types[15] = "Keyswitch - Momentary"
    log_event_types[16] = "Keyswitch - Latching"
    log_event_types[17] = "Security Key"
    log_event_types[18] = "Omit Key"
    log_event_types[19] = "Custom Alarm"
    log_event_types[20] = "Confirmed PA Audible"
    log_event_types[21] = "Confirmed PA Audible"
    log_event_types[22] = "Keypad Medical"
    log_event_types[23] = "Keypad Fire"
    log_event_types[24] = "Keypad Audible PA"
    log_event_types[25] = "Keypad Silent PA"
    log_event_types[26] = "Duress Code Alarm"
    log_event_types[27] = "Alarm Active"
    log_event_types[28] = "Bell Active"
    log_event_types[29] = "Re-arm"
    log_event_types[30] = "Verified Cross Zone Alarm"
    log_event_types[31] = "User Code"
    log_event_types[32] = "Exit Started"
    log_event_types[33] = "Exit Error (Arming Failed)"
    log_event_types[34] = "Entry Started"
    log_event_types[35] = "Part Arm Suite"
    log_event_types[36] = "Armed with Line Fault"
    log_event_types[37] = "Open/Close (Away Armed)"
    log_event_types[38] = "Part Armed"
    log_event_types[39] = "Auto Open/Close"
    log_event_types[40] = "Auto Arm Deferred"
    log_event_types[41] = "Open After Alarm (Alarm Abort)"
    log_event_types[42] = "Remote Open/Close"
    log_event_types[43] = "Quick Arm"
    log_event_types[44] = "Recent Closing"
    log_event_types[45] = "Reset After Alarm"
    log_event_types[46] = "Power O/P Fault"
    log_event_types[47] = "AC Fail"
    log_event_types[48] = "Low Battery"
    log_event_types[49] = "System Power Up"
    log_event_types[50] = "Mains Over Voltage"
    log_event_types[51] = "Telephone Line Fault"
    log_event_types[52] = "Fail to Communicate"
    log_event_types[53] = "Download Start"
    log_event_types[54] = "Download End"
    log_event_types[55] = "Log Capacity Alert (80%)"
    log_event_types[56] = "Date Changed"
    log_event_types[57] = "Time Changed"
    log_event_types[58] = "Installer Programming Start"
    log_event_types[59] = "Installer Programming End"
    log_event_types[60] = "Panel Box Tamper"
    log_event_types[61] = "Bell Tamper"
    log_event_types[62] = "Auxiliary Tamper"
    log_event_types[63] = "Expander Tamper"
    log_event_types[64] = "Keypad Tamper"
    log_event_types[65] = "Expander Trouble (Network error)"
    log_event_types[66] = "Remote Keypad Trouble (Network error)"
    log_event_types[67] = "Fire Zone Tamper"
    log_event_types[68] = "Zone Tamper"
    log_event_types[69] = "Keypad Lockout"
    log_event_types[70] = "Code Tamper Alarm"
    log_event_types[71] = "Soak Test Alarm"
    log_event_types[72] = "Manual Test Transmission"
    log_event_types[73] = "Automatic Test Transmission"
    log_event_types[74] = "User Walk Test Start/End"
    log_event_types[75] = "NVM Defaults Loaded"
    log_event_types[76] = "First Knock"
    log_event_types[77] = "Door Access"
    log_event_types[78] = "Part Arm 1"
    log_event_types[79] = "Part Arm 2"
    log_event_types[80] = "Part Arm 3"
    log_event_types[81] = "Auto Arming Started"
    log_event_types[82] = "Confirmed Alarm"
    log_event_types[83] = "Prox Tag"
    log_event_types[84] = "Access Code Changed/Deleted"
    log_event_types[85] = "Arm Failed"
    log_event_types[86] = "Log Cleared"
    log_event_types[87] = "iD Loop Shorted"
    log_event_types[88] = "Communication Port"
    log_event_types[89] = "TAG System Exit (Batt. OK)"
    log_event_types[90] = "TAG System Exit (Batt. LOW)"
    log_event_types[91] = "TAG System Entry (Batt. OK)"
    log_event_types[92] = "TAG System Entry (Batt. LOW)"
    log_event_types[93] = "Microphone Activated"
    log_event_types[94] = "AV Cleared Down"
    log_event_types[95] = "Monitored Alarm"
    log_event_types[96] = "Expander Low Voltage"
    log_event_types[97] = "Supervision Fault"
    log_event_types[98] = "PA from Remote FOB"
    log_event_types[99] = "RF Device Low Battery"
    log_event_types[100] = "Site Data Changed"
    log_event_types[101] = "Radio Jamming"
    log_event_types[102] = "Test Call Passed"
    log_event_types[103] = "Test Call Failed"
    log_event_types[104] = "Zone Fault"
    log_event_types[105] = "Zone Masked"
    log_event_types[106] = "Faults Overridden"
    log_event_types[107] = "PSU AC Fail"
    log_event_types[108] = "PSU Battery Fail"
    log_event_types[109] = "PSU Low Output Fail"
    log_event_types[110] = "PSU Tamper"
    log_event_types[111] = "Door Access"
    log_event_types[112] = "CIE Reset"
    log_event_types[113] = "Remote Command"
    log_event_types[114] = "User Added"
    log_event_types[115] = "User Deleted"
    log_event_types[116] = "Confirmed PA"
    log_event_types[117] = "User Acknowledged"
    log_event_types[118] = "Power Unit Failure"
    log_event_types[119] = "Battery Charger Fault"
    log_event_types[120] = "Confirmed Intruder"
    log_event_types[121] = "GSM Tamper"
    log_event_types[122] = "Radio Config. Failure"

    log_event_group_type = {}
    log_event_group_type[0] = "Not Reported"
    log_event_group_type[1] = "Priority Alarm"
    log_event_group_type[2] = "Priority Alarm Restore"
    log_event_group_type[3] = "Alarm"
    log_event_group_type[4] = "Restore"
    log_event_group_type[5] = "Open"
    log_event_group_type[6] = "Close"
    log_event_group_type[7] = "Bypassed"
    log_event_group_type[8] = "Unbypassed"
    log_event_group_type[9] = "Maintenance Alarm"
    log_event_group_type[10] = "Maintenance Restore"
    log_event_group_type[11] = "Tamper Alarm"
    log_event_group_type[12] = "Tamper Restore"
    log_event_group_type[13] = "Test Start"
    log_event_group_type[14] = "Test End"
    log_event_group_type[15] = "Disarmed"
    log_event_group_type[16] = "Armed"
    log_event_group_type[17] = "Tested"
    log_event_group_type[18] = "Started"
    log_event_group_type[19] = "Ended"
    log_event_group_type[20] = "Fault"
    log_event_group_type[21] = "Omitted"
    log_event_group_type[22] = "Reinstated"
    log_event_group_type[23] = "Stopped"
    log_event_group_type[24] = "Start"
    log_event_group_type[25] = "Deleted"
    log_event_group_type[26] = "Active"
    log_event_group_type[27] = "Not Used"
    log_event_group_type[28] = "Changed"
    log_event_group_type[29] = "Low Battery"
    log_event_group_type[30] = "Radio"
    log_event_group_type[31] = "Deactivated"
    log_event_group_type[32] = "Added"
    log_event_group_type[33] = "Bad Action"
    log_event_group_type[34] = "PA Timer Reset"
    log_event_group_type[35] = "PA Zone Lockout"

    def __init__(self, host, port, udl_password, message_handler_func):
        self.host = host
        self.port = port
        self.udlpassword = udl_password
        self.crc8_func = crcmod.mkCrcFun(poly=0x185, rev=False, initCrc=0xff)
        self.nextseq = 0
        self.message_handler_func = message_handler_func
        self.print_network_traffic = False
        self.last_command_time = 0
        self.last_received_seq = -1
        self.last_sequence = -1
        self.last_command = None
        self.panelType = None
        self.firmwareVersion = None
        self.numberOfZones = -1
        self.zone = {}
        self.user = {}
        self.area = {}
        self.s = None
        # used to record which of our idle commands we last sent to the panel
        self.lastIdleCommand = 0
        # Set to true if the idle loop should reread the site data
        self.siteDataChanged = False

    @staticmethod
    def hexstr(s):
        """Convert a binary string into a hex representation suitable for logging payloads etc"""
        return " ".join("{:02x}".format(ord(c)) for c in s)

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.CMD_TIMEOUT)
        self.s.connect((self.host, self.port))
        # if we send the login message to fast the panel ignores it; texecom
        # recommend 500ms, see:
        # http://texecom.websitetoolbox.com/post/show_single_post?pid=1303528828&postcount=4&forum=627911
        time.sleep(0.5)

    def getnextseq(self):
        if self.nextseq == 256:
            self.nextseq = 0
        nextseq = self.nextseq
        self.nextseq += 1
        return nextseq

    def closesocket(self):
        if self.s is not None:
            try:
                self.s.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            self.s.close()
            self.s = None

    def recvresponse(self):
        """Receive a response to a command. Automatically handles any
        messages that arrive first"""
        startTime = time.time()
        while True:
            if time.time() - startTime > self.CMD_TIMEOUT:
                # if we have had multiple event messages, we may get to the timeout time without the recv timing out
                raise socket.timeout
            assert self.last_command_time > 0
            time_since_last_command = time.time() - self.last_command_time
            if time_since_last_command > 30:
                # send any message to reset the panel's 60 second timeout
                # this ends up recursively calling recvresponse; however as our retry * timeout (3 * 2 == 6) is
                # far less than the 30 seconds between idle commands that won't be an issue
                if self.lastIdleCommand == 0:
                    result = self.get_date_time()
                elif self.lastIdleCommand == 1:
                    result = self.get_log_pointer()
                else:
                    result = self.get_system_power()
                self.lastIdleCommand += 1
                if self.lastIdleCommand == 3:
                    self.lastIdleCommand = 0
                if result is None:
                    self.log("idle command failed; closing socket")
                    self.closesocket()
                    return None
            header = self.s.recv(self.LENGTH_HEADER)
            if self.print_network_traffic:
                self.log("Received message header:")
                hexdump.hexdump(header)
            if header == "+++":
                self.log("Panel has forcibly dropped connection, possibly due to inactivity")
                self.closesocket()
                return None
            if header == "+++A":
                self.log("Panel is trying to hangup modem; probably connected too soon")
                self.closesocket()
                return None
            if len(header) == 0:
                self.log("Panel has closed connection")
                self.closesocket()
                return None
            if len(header) < self.LENGTH_HEADER:
                self.log("Header received from panel is too short, only {:d} bytes, ignoring - contents {}".format(
                    len(header), self.hexstr(header)))
                hexdump.hexdump(header)
                continue
            msg_start, msg_type, msg_length, msg_sequence = list(header)
            if msg_start != 't':
                self.log("unexpected msg start: " + hex(ord(msg_start)))
                hexdump.hexdump(header)
                return None
            expected_len = ord(msg_length) - self.LENGTH_HEADER
            payload = self.s.recv(expected_len)
            if self.print_network_traffic:
                self.log("Received message payload:")
                hexdump.hexdump(payload)
            if len(payload) < expected_len:
                self.log(
                    "Ignoring message, payload shorter than expected - got {:d} bytes, expected {:d} - contents {}".format(
                        len(payload), expected_len, self.hexstr(payload)))
                print("header:")
                hexdump.hexdump(header)
                print("payload:")
                hexdump.hexdump(payload)
                continue
            payload, msg_crc = payload[:-1], ord(payload[-1])
            expected_crc = self.crc8_func(header + payload)
            if msg_crc != expected_crc:
                self.log("crc: expected=" + str(expected_crc) + " actual=" + str(msg_crc))
                return None
            if msg_type == self.HEADER_TYPE_RESPONSE:
                if msg_sequence != self.last_sequence:
                    self.log(
                        "incorrect response seq: expected=" + str(self.last_sequence) + " actual=" + str(ord(msg_sequence)))
                    # recv again - either we receive the correct reply in the next packet, or we'll time out and retry the command
                    continue
            elif msg_type == self.HEADER_TYPE_MESSAGE:
                if self.last_received_seq != -1:
                    next_msg_seq = self.last_received_seq + 1
                    if next_msg_seq == 256:
                        next_msg_seq = 0
                    if msg_sequence == chr(self.last_received_seq):
                        self.log("ignoring message, sequence number is the same as last message: expected=" + str(
                            next_msg_seq) + " actual=" + str(ord(msg_sequence)))
                        continue
                    if msg_sequence != chr(next_msg_seq):
                        self.log("message seq incorrect - processing message anyway: expected=" + str(
                            next_msg_seq) + " actual=" + str(ord(msg_sequence)))
                        # process message anyway; perhaps we missed one or they arrived out of order
                self.last_received_seq = ord(msg_sequence)
            if msg_type == self.HEADER_TYPE_COMMAND:
                self.log("received command unexpectedly")
                return None
            elif msg_type == self.HEADER_TYPE_RESPONSE:
                return payload
            elif msg_type == self.HEADER_TYPE_MESSAGE:
                # FIXME: for "Site Data Changed" we should re-read the zone names etc - need to decode message
                # self.siteDataChanged = True
                self.message_handler_func(payload)

    def sendcommandbody(self, body):
        self.last_sequence = chr(self.getnextseq())
        data = self.HEADER_START + self.HEADER_TYPE_COMMAND + \
               chr(len(body) + 5) + self.last_sequence + body
        data += chr(self.crc8_func(data))
        if self.print_network_traffic:
            self.log("Sending command:")
            hexdump.hexdump(data)
        self.s.send(data)
        self.last_command = data

    def login(self):
        response = self.sendcommand(self.CMD_LOGIN, self.udlpassword)
        if response is None:
            self.log("sendcommand returned None for login")
            return False
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log("unexpected ack payload: " + hex(ord(response)))
            return False
        return True

    def set_event_messages(self):
        DEBUG_FLAG = 1
        ZONE_EVENT_FLAG = 1 << 1
        AREA_EVENT_FLAG = 1 << 2
        OUTPUT_EVENT_FLAG = 1 << 3
        USER_EVENT_FLAG = 1 << 4
        LOG_FLAG = 1 << 5
        events = ZONE_EVENT_FLAG | AREA_EVENT_FLAG | OUTPUT_EVENT_FLAG | USER_EVENT_FLAG | LOG_FLAG
        body = chr(events & 0xff) + chr(events >> 8)
        response = self.sendcommand(self.CMD_SETEVENTMESSAGES, body)
        if response == self.CMD_RESPONSE_NAK:
            self.log("NAK response from panel")
            return False
        elif response != self.CMD_RESPONSE_ACK:
            self.log("unexpected ack payload: " + hex(ord(response)))
            return False
        return True

    @staticmethod
    def log(string):
        timestamp = time.strftime("%Y-%m-%d %X")
        print(timestamp + ": " + string)

    def sendcommand(self, cmd, body):
        if body is not None:
            body = cmd + body
        else:
            body = cmd
        self.sendcommandbody(body)
        self.last_command_time = time.time()
        retries = self.CMD_RETRIES
        response = None
        while retries > 0:
            retries -= 1
            try:
                response = self.recvresponse()
                break
            except socket.timeout:
                self.log("Timeout waiting for response, resending last command")
                # NB: sequence number will be the same as last attempt
                self.last_command_time = time.time()
                self.s.send(self.last_command)

        self.last_command = None
        if response is None:
            return None

        commandid, payload = response[0], response[1:]
        if commandid != cmd:
            if commandid == self.CMD_LOGIN and payload[0] == self.CMD_RESPONSE_NAK:
                self.log("Received 'Log on NAK' from panel - session has timed out and needs to be restarted")
                return None
            self.log("Got response for wrong command id: Expected " + hex(ord(cmd)) + ", got " + hex(ord(commandid)))
            self.log("Payload: " + self.hexstr(payload))
            return None
        return payload

    def get_date_time(self):
        datetimeresp = self.sendcommand(self.CMD_GETDATETIME, None)
        if datetimeresp is None:
            return None
        if len(datetimeresp) < 6:
            self.log("GETDATETIME: response too short")
            self.log("Payload: " + self.hexstr(datetimeresp))
            return None
        datetimeresp = bytearray(datetimeresp)
        datetimestr = '20{2:02d}-{1:02d}-{0:02d} {3:02d}:{4:02d}:{5:02d}'.format(*datetimeresp)
        paneltime = datetime.datetime(2000 + datetimeresp[2], datetimeresp[1], datetimeresp[0], *datetimeresp[3:])
        seconds = int((paneltime - datetime.datetime.now()).total_seconds())
        if seconds > 0:
            diff = " (panel is ahead by {:d} seconds)".format(seconds)
        else:
            diff = " (panel is behind by {:d} seconds)".format(-seconds)
        self.log("Panel date/time: " + datetimestr + diff)
        return datetimestr

    def get_lcd_display(self):
        lcddisplay = self.sendcommand(self.CMD_GETLCDDISPLAY, None)
        if lcddisplay is None:
            return None
        if len(lcddisplay) != 32:
            self.log("GETLCDDISPLAY: response wrong length")
            self.log("Payload: " + self.hexstr(lcddisplay))
            return None
        self.log("Panel LCD display: " + lcddisplay)
        return lcddisplay

    def get_log_pointer(self):
        logpointerresp = self.sendcommand(self.CMD_GETLOGPOINTER, None)
        if logpointerresp is None:
            return None
        if len(logpointerresp) != 2:
            self.log("GETLOGPOINTER: response wrong length")
            self.log("Payload: " + self.hexstr(logpointerresp))
            return None
        logpointer = ord(logpointerresp[0]) + (ord(logpointerresp[1]) << 8)
        self.log("Log pointer: {:d}".format(logpointer))
        return logpointer

    def get_number_zones(self):
        idstr = self.get_panel_identification()
        if idstr is None:
            return None
        self.panelType, numberOfZones, something, self.firmwareVersion = idstr.split()
        self.numberOfZones = int(numberOfZones)

    def get_panel_identification(self):
        panelid = self.sendcommand(self.CMD_GETPANELIDENTIFICATION, None)
        if panelid is None:
            return None
        if len(panelid) != 32:
            self.log("GETPANELIDENTIFICATION: response wrong length")
            self.log("Payload: " + self.hexstr(panelid))
            return None
        self.log("Panel identification: " + panelid)
        return panelid

    def get_zone(self, zone_number):
        if zone_number not in self.zone:
            self.zone[zone_number] = Zone(zone_number)
        return self.zone[zone_number]

    def get_zone_details(self, zone_number):
        # zone is two bytes on 680
        details = self.sendcommand(self.CMD_GETZONEDETAILS, chr(zone_number))
        if details is None:
            return None
        zone = self.get_zone(zone_number)
        if len(details) == 34:
            zone.zoneType = ord(details[0])
            zone.areaBitmap = ord(details[1])
            zone.text = details[2:]
        elif len(details) == 35:
            zone.zoneType = ord(details[0])
            zone.areaBitmap = ord(details[1]) + (ord(details[2]) << 8)
            zone.text = details[3:]
        elif len(details) == 41:
            zone.zoneType = ord(details[0])
            zone.areaBitmap = ord(details[1]) + (ord(details[2]) << 8) + (ord(details[3]) << 16) + (
                        ord(details[4]) << 24) + \
                              (ord(details[5]) << 32) + (ord(details[6]) << 40) + (ord(details[7]) << 48) + (
                                          ord(details[8]) << 56)
            zone.text = details[9:]
        else:
            self.log("GETZONEDETAILS: response wrong length")
            self.log("Payload: " + self.hexstr(details))
            return None

        zone.text = zone.text.replace("\x00", " ")
        zone.text = re.sub(r'\W+', ' ', zone.text)
        zone.text = zone.text.strip()
        if zone.zoneType != self.ZONETYPE_UNUSED:
            self.log("zone {:d} type {} name '{}'".
                     format(zone.number, self.zone_types[zone.zoneType], zone.text))
        return zone

    def get_area_details(self, areaNumber):
        details = self.sendcommand(self.CMD_GETAREADETAILS, chr(areaNumber))
        if details is None:
            return None
        area = Area()
        if len(details) == 25:
            # first byte is area number
            areatext = details[1:17]
            areatext = areatext.replace("\x00", " ")
            areatext = re.sub(r'\W+', ' ', areatext)
            areatext = areatext.strip()
            area.name = areatext
            area.exitDelay = ord(details[17]) + (ord(details[18]) << 8)
            area.entry1Delay = ord(details[19]) + (ord(details[20]) << 8)
            area.entry2Delay = ord(details[21]) + (ord(details[22]) << 8)
            area.secondEntry = ord(details[23]) + (ord(details[24]) << 8)
        else:
            self.log("GETAREADETAILS: response wrong length")
            self.log("Payload: " + self.hexstr(details))
            return None
        self.log("area {:d} text '{}' exitDelay {:d} entry1 {:d} entry2 {:d} secondEntry {:d}".
                 format(areaNumber, area.name, area.exitDelay, area.entry1Delay, area.entry1Delay, area.secondEntry))
        return area

    @staticmethod
    def bcdDecode(bcd):
        result = ""
        for char in bcd:
            for val in (ord(char) >> 4, ord(char) & 0xF):
                if val <= 9:
                    result += str(val)
        return result

    def get_user(self, usernumber):
        # panel may support more than 255 users, in which case this needs 2 bytes
        # body = chr(usernumber & 0xff)+chr(usernumber >> 8)
        body = chr(usernumber)
        details = self.sendcommand(self.CMD_GETUSER, body)
        if details is None:
            return None
        user = User()
        if len(details) == 23:
            username = details[0:8]
            username = username.replace("\x00", " ")
            username = re.sub(r'\W+', ' ', username)
            username = username.strip()
            user.name = username
            user.passcode = self.bcdDecode(details[8:11])
            user.areas = ord(details[11])
            user.modifiers = details[12]
            user.locks = details[13]
            user.doors = details[14:17]
            user.tag = self.bcdDecode(details[17:21])  # last byte always 0xff
            user.config = ord(details[21]) + (ord(details[22]) << 8)
        else:
            # there are other lengths but I have no way to test
            self.log("GETUSER: unexpected response length {:d}".format(len(details)))
            self.log("Payload: " + self.hexstr(details))
            return None

        if user.valid():
            self.log("user {:d} name '{}'".
                     format(usernumber, user.name))
        return user

    def get_system_power(self):
        details = self.sendcommand(self.CMD_GETSYSTEMPOWER, None)
        if details is None:
            return None
        if len(details) != 5:
            self.log("GETSYSTEMPOWER: response wrong length")
            self.log("Payload: " + self.hexstr(details))
            return None
        ref_v = ord(details[0])
        sys_v = ord(details[1])
        bat_v = ord(details[2])
        sys_i = ord(details[3])
        bat_i = ord(details[4])

        system_voltage = 13.7 + ((sys_v - ref_v) * 0.070)
        battery_voltage = 13.7 + ((bat_v - ref_v) * 0.070)

        system_current = sys_i * 9
        battery_current = bat_i * 9

        self.log("System power: system voltage {:f} battery voltage {:f} system current {:d} battery current {:d}".
                 format(system_voltage, battery_voltage, system_current, battery_current))
        return (system_voltage, battery_voltage, system_current, battery_current)

    def get_all_zones(self):
        for zoneNumber in range(1, self.numberOfZones + 1):
            zone = self.get_zone_details(zoneNumber)
            self.zone[zoneNumber] = zone

    def get_all_users(self):
        panel_users = {12: 8, 24: 25, 48: 50, 64: 50, 88: 100, 168: 200, 640: 1000}
        for usernumber in range(1, panel_users[self.numberOfZones]):
            user = self.get_user(usernumber)
            if user.valid():
                self.user[usernumber] = user
        user = User()
        user.name = "Engineer"
        self.user[0] = user

    def get_all_areas(self):
        panel_areas = {12: 2, 24: 2, 48: 4, 64: 4, 88: 8, 168: 16, 640: 64}
        for areanumber in range(1, panel_areas[self.numberOfZones]):
            area = self.get_area_details(areanumber)
            self.area[areanumber] = area

    def get_site_data(self):
        self.get_all_areas()
        self.get_all_zones()
        self.get_all_users()

    def event_loop(self):
        lastConnectedAt = time.time()
        notifiedConnectionLoss = False
        connected = False
        while True:
            if connected:
                lastConnectedAt = time.time()
                connected = False
                notifiedConnectionLoss = False
                self.log("Connection lost")
            connectionLostTime = time.time() - lastConnectedAt
            if connectionLostTime >= 60 and not notifiedConnectionLoss:
                self.log("Connection lost for over 60 seconds - calling send-message.sh")
                os.system("./send-message.sh 'connection lost'")
                notifiedConnectionLoss = True
            try:
                self.connect()
            except socket.error as e:
                self.log("Connect failed - {}; sleeping for 5 seconds".format(e))
                time.sleep(5)
                continue
            if not self.login():
                self.log(
                    "Login failed - udl password incorrect, pre-v4 panel, or trying to connect too soon: closing socket, try again 5 in seconds")
                time.sleep(5)
                self.closesocket()
                continue
            self.log("login successful")
            if not self.set_event_messages():
                self.log("Set event messages failed, closing socket")
                self.closesocket()
                continue
            connected = True
            if notifiedConnectionLoss:
                self.log("Connection regained - calling send-message.sh")
                os.system("./send-message.sh 'connection regained'")
            self.get_number_zones()
            self.get_date_time()
            self.get_system_power()
            self.get_log_pointer()
            self.get_site_data()
            self.log("Got all areas/zones/users; waiting for events")
            while self.s is not None:
                try:
                    for zone in self.zone.values():
                        zone.update()
                    if self.siteDataChanged:
                        self.siteDataChanged = False
                        self.get_site_data()
                    self.recvresponse()

                except socket.timeout:
                    # we didn't send any command, so a timeout is the expected result, continue our loop
                    continue

    def decode_message_to_text(self, payload):
        msg_type, payload = payload[0], payload[1:]
        if msg_type == self.MSG_DEBUG:
            return "Debug message: " + self.hexstr(payload)
        elif msg_type == self.MSG_ZONEEVENT:
            if len(payload) == 2:
                zone_number = ord(payload[0])
                zone_bitmap = ord(payload[1])
            elif len(payload) == 3:
                zone_number = ord(payload[0]) + (ord(payload[1]) << 8)
                zone_bitmap = ord(payload[2])
            else:
                return "unknown zone event message payload length"
            zone_state = zone_bitmap & 0x3
            zone_str = ["secure", "active", "tamper", "short"][zone_state]
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
            if zone_number in self.zone:
                zone_text = self.zone[zone_number].text
            else:
                zone_text = "unknown zone"
            return "Zone event message: zone {:d} '{}' {}". \
                format(zone_number, zone_text, zone_str)
        elif msg_type == self.MSG_AREAEVENT:
            area_number = ord(payload[0])
            area_state = ord(payload[1])
            area_state_str = ["disarmed", "in exit", "in entry", "armed", "part armed", "in alarm"][area_state]
            if area_number in self.area:
                areaname = self.area[area_number].name
            else:
                areaname = "unknown"
            return "Area event message: area {:d} {} {}".format(area_number, areaname, area_state_str)
        elif msg_type == self.MSG_OUTPUTEVENT:
            locations = ["Panel outputs",
                         "Digi outputs",
                         "Digi Channel low 8",
                         "Digi Channel high 8",
                         "Redcare outputs",
                         "Custom outputs 1",
                         "Custom outputs 2",
                         "Custom outputs 3",
                         "Custom outputs 4",
                         "X-10 outputs"]
            output_location = ord(payload[0])
            output_state = ord(payload[1])
            if output_location < len(locations):
                output_name = locations[output_location]
            elif (output_location & 0xf) == 0:
                output_name = "Network {:d} keypad outputs". \
                    format(output_location >> 4, output_location & 0xf)
            else:
                output_name = "Network {:d} expander {:d} outputs". \
                    format(output_location >> 4, output_location & 0xf)
            return "Output event message: location {:d}['{}'] now 0x{:02x}". \
                format(output_location, output_name, output_state)
        elif msg_type == self.MSG_USEREVENT:
            user_number = ord(payload[0])
            user_state = ord(payload[1])
            user_state_str = ["code", "tag", "code+tag"][user_state]
            if user_number in self.user:
                name = self.user[user_number].name
            else:
                name = "unknown"
            return "User event message: logon by user '{}' {:d} {}". \
                format(name, user_number, user_state_str)
        elif msg_type == self.MSG_LOGEVENT:
            if len(payload) == 8:
                parameter = ord(payload[2])
                areas = ord(payload[3])
                timestamp = payload[4:8]
            elif len(payload) == 9:
                # Premier 168 - longer message as 16 bits of area info
                parameter = ord(payload[2])
                areas = ord(payload[3]) + (ord(payload[8]) << 8)
                timestamp = payload[4:8]
            elif len(payload) == 10:
                # Premier 640
                # I'm unsure if this is correct and I don't have a panel to test with
                parameter = ord(payload[2]) + (ord(payload[3]) << 8)
                areas = ord(payload[4]) + (ord(payload[5]) << 8)
                timestamp = payload[6:10]
            else:
                return "unknown log event message payload length"

            event_type = ord(payload[0])
            group_type_msg = ord(payload[1])
            timestamp_int = ord(timestamp[0]) + (ord(timestamp[1]) << 8) + (ord(timestamp[2]) << 16) + (
                        ord(timestamp[3]) << 24)
            seconds = timestamp_int & 63
            minutes = (timestamp_int >> 6) & 63
            month = (timestamp_int >> 12) & 15
            hours = (timestamp_int >> 16) & 31
            day = (timestamp_int >> 21) & 31
            year = 2000 + ((timestamp_int >> 26) & 63)
            timestamp_str = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(year, month, day, hours, minutes,
                                                                               seconds)

            if event_type in self.log_event_types:
                event_str = self.log_event_types[event_type]
            else:
                event_str = "Unknown log event type {:d}".format(event_type)

            group_type = group_type_msg & 0b00111111
            comm_delayed = group_type_msg & 0b01000000
            communicated = group_type_msg & 0b10000000

            if group_type in self.log_event_group_type:
                group_type_str = self.log_event_group_type[group_type]
            else:
                group_type_str = "Unknown log event group type {:d}".format(group_type)

            if comm_delayed:
                group_type_str += " [comm delayed]"
            if communicated:
                group_type_str += " [communicated]"

            return "Log event message: {} {}, {}  parameter: {:d}   areas: {:d}".format(timestamp_str, event_str,
                                                                                        group_type_str, parameter,
                                                                                        areas)
        else:
            return "unknown message type " + str(ord(msg_type)) + ": " + self.hexstr(payload)

def message_handler(payload):
    tc.log(tc.decode_message_to_text(payload))
    msg_type, payload = payload[0], payload[1:]
    if msg_type == tc.MSG_ZONEEVENT:
        zone_number = ord(payload[0])
        zone_bitmap = ord(payload[1])
        zone = tc.get_zone(zone_number)
        zone.state = zone_bitmap & 0x3
        if zone.state == 1:
            zone.active = True
        else:
            zone.active = False

# disable buffering to stdout when it's redirected to a file/pipe
# This makes sure any events appear immediately in the file/pipe,
# instead of being queued until there is a full buffer's worth.
class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

if __name__ == '__main__':
    texhost = os.getenv('TEXHOST','192.168.1.9')
    texport = os.getenv('TEXPORT',10001)
    # This is the default UDL password for a factory panel. For any real
    # installation, use wintex to set the UDL password in the panel to a
    # random 16 character alphanumeric string.
    udlpassword = os.getenv('UDLPASSWORD','1234')

    sys.stdout = Unbuffered(sys.stdout)
    tc = TexecomConnect(texhost, texport, udlpassword, message_handler)
    tc.event_loop()
