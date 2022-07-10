# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_domain_to_ip
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Pablo Salinas
#
# Created:     10/07/2022
# Copyright:   (c) Pablo Salinas
# Licence:     GPL
# -------------------------------------------------------------------------------

import subprocess
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class spf_domain_to_ip(SpiderFootPlugin):

    meta = {
        'name': "nslookup",
        'summary': "This module returns the IP associated to a domain executing nslookup command",
        'flags': [""],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            
            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")
            #We obtain the information using nslookup command
            data = subprocess.run ('nslookup '+eventData, shell=True, capture_output=True, text=True)
            output_cmd = str(data.stdout)
            #We save each IP in ips variable
            ips=output_cmd.split('\n')
            
            if not ips:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return

        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        #We iterate over the input and print the IP/IPs parsed that were found
        for a in ips:
            evt = SpiderFootEvent(eventName, a, self.__name__, event)
            self.notifyListeners(evt)

# End of spf_domain_to_ip class
