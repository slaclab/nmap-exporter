#!/usr/bin/env python3

from prometheus_client import start_http_server, Summary, REGISTRY
from prometheus_client.core import GaugeMetricFamily, REGISTRY
import time
import subprocess
import os
from xml.etree import ElementTree
import logging

logging.basicConfig(level=logging.INFO)

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

SLEEP = int(os.environ.get("NMAP_COLLECTOR_INTERVAL",30))
PORT = int(os.environ.get("NMAP_COLLECTOR_PORT",8000))
IP_RANGE = os.environ.get("NMAP_COLLECTOR_IP_RANGE",'192.168.0.0/24')



class NmapMetrics(object):

    def __init__(self, polling_interval=60):
        self.polling_interval = polling_interval
        self.reset_metrics()

    def reset_metrics(self):
        self.ping = GaugeMetricFamily(
            'nmap_ping_srtt_ms',
            'Ping times of all network devices (devices are labels)',
            labels=["hostname", "ip_address"]
        )
        self.state = GaugeMetricFamily(
            'nmap_port_state',
            'Discovered port state of network devices (devices are labels)',
            labels=["hostname", "ip_address", "proto", "portid", "service", "status"]
        )

    def run_metrics_loop(self):
        while True:
            self.fetch()
            time.sleep( self.polling_interval )

    def collect(self):
        yield self.ping
        yield self.state

    @REQUEST_TIME.time()
    def fetch(self):

        # purge items
        self.reset_metrics()

        logging.info("scanning")

        filename = f"/tmp/nmap-{time.time()}"

        subprocess.Popen(
            ["nmap", "-oX", filename, "-d3", "-F", IP_RANGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).wait()

        root = ElementTree.parse(filename).getroot()
        for n in root.findall("host"):
            address = n.find("address").attrib["addr"]
            hostname = None
            try:
                hostnames_el = n.find("hostnames").find("hostname")
                if hostnames_el is not None:
                    hostname = hostnames_el.attrib["name"]
                else:
                    hostname = address
            except:
                hostname = address
            logging.info(f"found node {address} ({hostname})")

            # parse ping
            ping_time = None
            try:
                ping_time = int(n.find("times").attrib["srtt"]) / 1000
            except:
                ping_time = 0
            self.ping.add_metric([hostname, address], ping_time)

            ports = n.find("ports")
            if ports:
                for port in ports:
                    #logging.debug(f"found port {port}")
                    try:
                        proto = port.attrib["protocol"]
                        portid = port.attrib["portid"]
                        service = port.find("service").attrib["name"]
                        status = port.find("state").attrib["state"]
                        stat = 0
                        if status == 'open':
                            stat = 1
                        elif status == 'filtered':
                            stat = -2
                        elif status == 'unfiltered':
                            stat = -1 
                        logging.debug(f"PORT proto: {proto} portid: {portid} service: {service} status: {status} / {stat}")
                        self.state.add_metric( [hostname, address, proto, portid, service, status], stat )
                    except:
                        pass

        os.remove(filename)
        logging.info("scan completed")


def main():
    nmap_metrics = NmapMetrics( polling_interval=SLEEP )
    REGISTRY.register( nmap_metrics )
    start_http_server(PORT)
    nmap_metrics.run_metrics_loop()

if __name__ == '__main__':
    main()
