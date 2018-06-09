# Texecom Connect Protocol Python

## Introduction

This is a python module and a quick example that implements decoding of the Texecom Connect protocol.

## Requirements

This module connects over TCP to the alarm panel, so a ComIP or SmartCom is needed.

The ComIP/SmartCom only allow one TCP connection to be made to them, so you will need to dedicate one to this purpose. Whilst this program is running, the SmartCom/ComIP will not be able to send out events to notification centers or to the texecom applications - I believe except for when an alarm occurs, in which case the connection to this program will be forcibly dropped by the panel. 

Your alarm panel must be a Premier Elite panel running firmware version 4.0 or higher.

You need to set a UDL password for your panel. If you don't have a UDL password and do not have the engineer code you will not be able to use this code.

## Current status

The module currently decodes every event I've seen from the panel, and polls the panel for information like current time / voltage levels. It subscribes to all events from the alarm panel, so will display any zone changes, arm/disarm, etc.

It does not currently support arm/disarming.

It allows the caller to register handlers for zone activation events.

My own main use for this module is:

1. Keeping a log of everything that happens in the alarm system
2. Using zone activations to push notifications to my iPhone/Apple watch, including frame grabs from my external IP cameras - I do this using https://pushover.net

## Using it

You need python installed, including the crcmod ('sudo -s pip install crcmod' will install it if you don't have it). The module is written in python2 but I believe could be made compatible with python3 as well with some fairly easy changes.

clone this git repo, then edit alarm-monitor.py to have the correct IP address, port number and UDL password, then just run the script:

`./alarm-monitor.py`

## Contributions

Contributions are most welcome. Please feel free to open a merge request. I'm interested in taking this further with help from others, potentially adding a web interface, mqtt, a mobile app, etc.

## License

Copyright (C) 2018 Joseph Heenan

Licensed under the Apache License, Version 2.0;
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

## Texecom NDA

This module was developed using information provided to me by Texecom under NDA.

I cannot share that documentation with anyone and can not answer questions about what this documentation says - you are free to sign your own NDA with Texecom to receive the same documentation.

The NDA was not clear as to whether software that used the information received under NDA could be distributed or not. I explicitly asked Texecom if this software could be distributed (including sending them a copy of the python code) and received this response on 8th June 2018:

> I have spoken to the team who approve the NDA’s and they have stated that you are able to release your program but you cannot disclose details of the protocol documentation.

Whilst still slightly oddly worded, they do say they are happy with me releasing this python code.
