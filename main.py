#!/usr/bin/env python

import os
import sys
import nmap
import time
import discord
import asyncio
import logging

try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(0)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(0)

logger = logging.getLogger('discord')
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(filename='IDS010.log', encoding='utf-8', mode='w')
handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
logger.addHandler(handler)

hosts = []
TTL = 3
localtime = time.asctime(time.localtime(time.time()))

class IDS010(discord.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bg_task = self.loop.create_task(self.seeker_bg_task())

    @client.event
    async def on_ready(self):
        print('{0.user} is ready'.format(client))

    @client.event
    async def on_message(message):
        if message.author == client.user:
            return
        if message.content.startswith('$hello'):
            await message.channel.send('Hello!')

    @staticmethod
    def seek():
        shosts = []
        nm.scan(hosts = '192.168.1.0/24', arguments = '-n -sn -PE -T4')

        for host in nm.all_hosts():
            try:
                mac = nm[host]['addresses']['mac']
                vendor = nm[host]['vendor'][mac]
            except:
                vendor = mac = 'unknown'

            shosts.append((host,mac,vendor,TTL))
        return shosts

    @staticmethod
    async def update(shosts, channel):
        global hosts
        if hosts == shosts:
            return

        elif hosts == []:
            hosts = shosts
            fmt = '=== Devices Already Connected : {0} ===\n'.format(localtime)
            fmt += ''.join('\nIP Address: {}\nMAC Address: {}\nVendor: {}\n'.format(*x) for x in shosts)
            await channel.send(fmt)

        else:
            newhosts = shosts - hosts
            ghosts = hosts - shosts
            for host in newhosts:
                hosts.append(host)
                fmt = '+++ Device Connected : {0} +++'.format(localtime)
                fmt += ''.join('\nIP Address: {}\nMAC Address: {}\nVendor: {}\n'.format(*host))
                await channel.send(fmt)

            for host in hosts:
                if any(host[0] == ghost[0] for ghost in ghosts):
                    host[3] -= 1
                if host[3] <= 0:
                    hosts.remove(host)
                    fmt = '--- Device Disconnected : {0} ---'.format(localtime)
                    fmt += ''.join('\nIP Address: {}\nMAC Address: {}\nVendor: {}\n'.format(*host))
                    await channel.send(fmt)

    async def seeker_bg_task(self):
        await self.wait_until_ready()
        channel = self.get_channel(*************) # Channel ID

        while not self.is_closed():
            scan = self.seek()
            await self.update(scan, channel)
            await asyncio.sleep(0.5) # task runs every half second

client = IDS010()
client.run('TOKEN')