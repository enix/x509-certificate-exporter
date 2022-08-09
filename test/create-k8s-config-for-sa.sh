#! /bin/bash
set -euo pipefail

kubectl="kubectl --insecure-skip-tls-verify"
server=$(TERM=dumb $kubectl config view --minify | grep server | cut -f 2- -d ":" | tr -d " ")
name=$($kubectl describe sa $1 | grep 'Tokens:' | awk '{ print $2 }')
ca=$($kubectl get secret/$name -o jsonpath='{.data.ca\.crt}')
token=$($kubectl get secret/$name -o jsonpath='{.data.token}' | base64 -d)
namespace=$($kubectl get secret/$name -o jsonpath='{.data.namespace}' | base64 -d)

echo "
apiVersion: v1
kind: Config
clusters:
- name: default-cluster
  cluster:
    certificate-authority-data: ${ca}
    server: ${server}
contexts:
- name: default-context
  context:
    cluster: default-cluster
    namespace: default
    user: default-user
current-context: default-context
users:
- name: default-user
  user:
    token: ${token}
" > kubeconfig.$1
