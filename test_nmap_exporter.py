import pytest
import nmap_exporter as ne

"""
NMAP_COLLECTOR_IP_RANGE="google.com totally.bogus.nonexistentdomain5273.foobar s3df.slac.stanford.edu grafana.slac.stanford.edu influxdb.slac.stanford.edu prometheus.slac.stanford.edu k8s.slac.stanford.edu sdfrepo.sdf.slac.stanford.edu sdfregistry001.slac.stanford.edu coact.slac.stanford.edu sdfloki.slac.stanford.edu" NMAP_COLLECTOR_SCAN_METHOD="-sT -T4 -p443 --script ssl-cert --max-parallelism=1000 --script-timeout=10 --host-timeout=15" docker run -e NMAP_COLLECTOR_IP_RANGE -e NMAP_COLLECTOR_SCAN_METHOD -p 8000:8000 nmap-exporter:test
"""
