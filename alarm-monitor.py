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

from __future__ import print_function

import os
import sys
import json

from texecomConnect import TexecomConnect

import paho.mqtt.client as paho

broker_url = os.getenv('BROKER_URL','192.168.1.1')
broker_port = os.getenv('BROKER_PORT',1883)
broker_user = os.getenv('BROKER_USER',None)
broker_pass = os.getenv('BROKER_PASS',None)

def on_message(client, userdata, message):
    time.sleep(1)
    print("received message =",str(message.payload.decode("utf-8")))

client = paho.Client()

client.username_pw_set(broker_user, broker_pass)
client.on_message=on_message

print("connecting to broker ", broker_url)
client.connect(broker_url, broker_port)
client.loop_start()

class TexecomConnectMqtt(TexecomConnect):
    # Overload get_zone_details to publish zone information to MQTT
    def get_zone_details(self, zone_number):
        zone = super(TexecomConnectMqtt, self).get_zone_details(zone_number)
        if zone.zoneType != self.ZONETYPE_UNUSED:
            if zone.zoneType == 1:
                HAZoneType = "door"
            elif zone.zoneType == 8:
                HAZoneType = "safety"
            else:
                HAZoneType = "motion"
            name = str.lower((zone.text).replace(" ", "_"))
            topicbase = str("homeassistant/binary_sensor/" + name)
            configtopic = str(topicbase + "/config")
            statetopic = str(topicbase + "/state")
            message = {
                "name": name,
                "device_class": HAZoneType,
                "state_topic": statetopic,
                "payload_on": "1",
                "payload_off": "0",
                "unique_id": ".".join([self.panelType, name]),
                "device": {
                    "name": "Texecom " + self.panelType + " " + str(self.numberOfZones),
                    "identifiers": "123456789", #TODO panel serial number?
                    "manufacturer": "Texecom",
                    "model": self.panelType + " " + str(self.numberOfZones)
                }
            }
            # self.log(configtopic + ":" + json.dumps(message))
            client.publish(configtopic,json.dumps(message), retain=True)
        return zone

    # Overload get_area_details to publish area information to MQTT
    def get_area_details(self, areaNumber):
        area = super(TexecomConnectMqtt, self).get_area_details(areaNumber)
        name = str.lower((area.name).replace(" ", "_"))
        topicbase = str("homeassistant/alarm_control_panel/" + name)
        configtopic = str(topicbase + "/config")
        statetopic = str(topicbase + "/state")
        commandtopic = str(topicbase + "/command")
        message = {
            "name": name,
            "state_topic": statetopic,
            "command_topic": commandtopic,
            "unique_id": ".".join([self.panelType, "area", name]),
            "device": {
                "name": "Texecom " + self.panelType + " " + str(self.numberOfZones),
                "identifiers": "123456789", #TODO panel serial number?
                "manufacturer": "Texecom",
                "model": self.panelType + " " + str(self.numberOfZones)
            }
        }
        # self.log(configtopic + ":" + json.dumps(message))
        client.publish(configtopic,json.dumps(message), retain=True)
        return area


def message_handler(payload):
    tc.log(tc.decode_message_to_text(payload))
    msg_type, payload = payload[0], payload[1:]
    if msg_type == tc.MSG_ZONEEVENT:
        zone_number = ord(payload[0])
        zone_bitmap = ord(payload[1])
        zone = tc.get_zone(zone_number)
        zone.state = zone_bitmap & 0x3
        topic = "homeassistant/binary_sensor/"+str.lower((zone.text).replace(" ", "_"))+"/state"
        if zone.state == 1:
            zone.active = True
        else:
            zone.active = False
        tc.log("MQTT Update %s: %s" % (topic, zone.state))
        client.publish(topic,zone.state)
    elif msg_type == tc.MSG_AREAEVENT:
        area_number = ord(payload[0])
        area_state = ord(payload[1])
        area_state_str = ["disarmed", "pending", "pending", "armed_away", "armed_night", "triggered"][area_state]
        area = tc.get_area(area_number)
        area.state = area_state_str
        topic = "homeassistant/alarm_control_panel/" + str.lower((area.name).replace(" ", "_"))+"/state"
        tc.log("MQTT Update %s: %s" % (topic, area.state))
        client.publish(topic, area.state)


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
    tc = TexecomConnectMqtt(texhost, texport, udlpassword, message_handler)
    tc.event_loop()
