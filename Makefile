#!/usr/bin/make

SHELL = /bin/sh

CURRENT_UID := $(shell id -u)
PWD = $(shell pwd)

helm-docs_%:
	docker run --rm --volume "$(PWD)/$*:/helm-docs" -u $(CURRENT_UID) jnorwood/helm-docs:latest helm-docs --template-files=README.md.gotmpl --chart-search-root=.

json-schema_%:
	yq -j e $(PWD)/$*/values.yaml > $(PWD)/$*/values.json
	genson $(PWD)/$*/values.json | jq '.' > $(PWD)/$*/values.schema.json
	rm $(PWD)/$*/values.json