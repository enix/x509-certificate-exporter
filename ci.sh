#! /bin/bash

version="$1"
notes="$2"
containsSecurityUpdates="$3"

prerelease="false"
versionComponents=(${version//-/ })

if [ ! -z "${versionComponents[1]}" ]; then
	prerelease="true"
fi

yq -i ".version = \"$version\"" Chart.yaml
yq -i ".appVersion = \"$version\"" Chart.yaml
yq -i ".annotations[\"artifacthub.io/prerelease\"] = \"$prerelease\"" Chart.yaml
yq -i ".annotations[\"artifacthub.io/containsSecurityUpdates\"] = \"$containsSecurityUpdates\"" Chart.yaml
yq -i ".annotations[\"artifacthub.io/changes\"] = \"$(echo "$notes" | sed "s/\\\"/\\\\\"/g")\"" Chart.yaml
