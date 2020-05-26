#!/usr/bin/env python
# -*- coding: utf-8 -*-

from protectwise import * 

a = get_event_info(2)
b = [i for i in a]

for i in b:
    if i['workflow']['resolution'] is None:
        get_pcap(i['id'], 'PW_' + i['id'] + '_' +  str(i['threatScore']))
