# Installation for Linux

If you wish to run the exporter with systemd, a service file available here.  
We do not build packages for any distro and recommend the use of an automated configuration system such as Ansible.

Security can be improved with mTLS using [exporter_exporter](https://github.com/QubitProducts/exporter_exporter).

## Quick Install

Use this shell snippet for evaluation or a quick-and-dirty deployment.

```bash
# replace with latest version released
VERSION=3.X.X

TMP=$(mktemp)
curl -L -o ${TMP} https://github.com/enix/x509-certificate-exporter/releases/download/v${VERSION}/x509-certificate-exporter-linux-amd64
sudo install -o root -g root -m 755 ${TMP} /usr/local/bin/x509-certificate-exporter
curl -L -o ${TMP} https://raw.githubusercontent.com/enix/x509-certificate-exporter/master/deploy/linux/x509-certificate-exporter.service
sudo install -o root -g root -m 644 ${TMP} /etc/systemd/system/x509-certificate-exporter.service
rm -f ${TMP}

# edit exporter arguments in /etc/systemd/system/x509-certificate-exporter.service
# no configuration is supported

sudo systemctl daemon-reload
sudo systemctl enable --now x509-certificate-exporter
sudo systemctl status x509-certificate-exporter
```
