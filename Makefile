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
 
test-bash: venv pip
	$(CONTAINER_RT) build -t $(REPO):test .
	$(CONTAINER_RT) run -it $(REPO):test bash
