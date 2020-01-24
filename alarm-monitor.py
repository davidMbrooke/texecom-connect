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
            topicbase = str("homeassistant/binary_sensor/" + str.lower((zone.text).replace(" ", "_")))
            configtopic = str(topicbase + "/config")
            statetopic = str(topicbase + "/state")
            message = {
                "name": str.lower(zone.text).replace(" ", "_"),
                "device_class": HAZoneType,
                "state_topic": statetopic,
                "payload_on": 1,
                "payload_off": 0,
                "unique_id": id(zone)
                }
            # print(json.dumps(message))
            client.publish(configtopic,json.dumps(message))
        return zone

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
        client.publish(topic,zone.state)


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
