CONTAINER_RT ?= podman
REPO ?= slaclab/nmap-exporter
TAG ?= latest

venv:
	python3 -m venv .

pip:
	./bin/pip3 install -r requirements.txt

clean:
	rm -rf bin include lib  lib64

build:
	$(CONTAINER_RT) build -t $(REPO):$(TAG) .

push:
	$(CONTAINER_RT) push $(REPO):$(TAG)
 

#######################
# tests
#######################
pip-pytest:
	./bin/pip3 install -r requirements-pytest.txt

pytest:
	./bin/

test-bash: venv pip
	$(CONTAINER_RT) build -t $(REPO):test .
	$(CONTAINER_RT) run -it $(REPO):test bash

test-run:
	$(CONTAINER_RT) run -p 8000:8000 $(REPO):test

docker-local-8000-s3df-services-test:
	docker build -t $(REPO):test .
	NMAP_COLLECTOR_IP_RANGE="google.com totally.bogus.nonexistentdomain5273.foobar s3df.slac.stanford.edu grafana.slac.stanford.edu influxdb.slac.stanford.edu prometheus.slac.stanford.edu k8s.slac.stanford.edu sdfrepo.sdf.slac.stanford.edu sdfregistry001.slac.stanford.edu coact.slac.stanford.edu sdfloki.slac.stanford.edu" NMAP_COLLECTOR_SCAN_METHOD="-sT -T4 -p443 --script ssl-cert --max-parallelism=1000 --script-timeout=10 --host-timeout=15" docker run -e NMAP_COLLECTOR_IP_RANGE -e NMAP_COLLECTOR_SCAN_METHOD -p 8000:8000 nmap-exporter:test
