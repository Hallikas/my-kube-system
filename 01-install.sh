#!/bin/bash

DOMAIN=gamehost.fi
SYSTEMURL=test.${DOMAIN}
ENGINE=rke2
# microk8s engine support not yet configured
#ENGINE=microk8s

# Add list of your 3 master nodes here, including current one, update grep line also!
grep -q testkube2 /etc/hosts || cat <<EOF >> /etc/hosts
37.27.207.147 testkube1 testkube1.${DOMAIN}
37.27.194.169 testkube2 testkube2.${DOMAIN}
37.27.212.12 testkube3 testkube3.${DOMAIN}
EOF

SSHPORT="22"
TOKEN=$(openssl rand -hex 48)
NODES=$(grep "gamehost.fi$" /etc/hosts|cut -d' ' -f2)

###### PRE CHECK
# Do we have SSH key?
[ ! -e ~/.ssh/id_rsa ] && echo "Upload SSH keys"
until [ -e ~/.ssh/id_rsa ]; do
	echo "Make sure that ~/.ssh/id_rsa" exists
	sleep 10
done

for NODE in ${NODES};do
	[ "${NODE}" = "$(hostname -s)" ] && continue
	ssh -p ${SSHPORT} root@${NODE}.${DOMAIN} "id"
done

echo "Ready to continue";read

mkdir -p conf

cat <<'EOF' > /etc/resolv-ipv4.conf
nameserver 8.8.8.8
nameserver 185.12.64.1
nameserver 1.1.1.1
search .
EOF

cat <<'EOF' > .nodesh.tmp
apt-get update
apt-get install -y joe jq open-iscsi nfs-common cifs-utils && systemctl enable iscsid
echo 'dm_crypt' > /etc/modules-load.d/dm_crypt.conf
echo 'iscsi_tcp' > /etc/modules-load.d/iscsi_tcp.conf
modprobe iscsi_tcp
modprobe dm_crypt

systemctl disable multipathd.service
systemctl disable multipathd.socket

mkdir -p /data2/hostpath /data2/longhorn
mkdir -p /root/.kube
EOF

# MicroK8s
if [ "${ENGINE}" = "microk8s" ]; then
[ -e /etc/microk8s.yaml ] || cat <<'EOF' > /etc/microk8s.yaml
version: 0.2.0
extraKubeAPIServerArgs:
  --service-node-port-range: 0-65535
# --authorization-mode: RBAC,Node
extraKubeletArgs:
  --resolv-conf: /etc/resolv-ipv4.conf
  --cluster-dns: 10.152.183.10
  --cluster-domain: cluster.local
extraSANs:
  - ${SYSTEMURL}
addonRepositories:
  - name: core
    url: https://github.com/canonical/microk8s-core-addons
addons:
  - name: dns
  - name: hostpath-storage
  - name: cert-manager
  - name: ingress
    args: [default-ssl-certificate=cert-manager/tls-wildcard]
  - name: dashboard
    disable: true
EOF

cat <<'EOF' >> .nodesh.tmp
snap install microk8s --classic --channel=1.30/stable
sleep 2 && microk8s status --wait-ready

microk8s config > /root/.kube/config
EOF
fi

# RKE2
if [ "${ENGINE}" = "rke2" ]; then
mkdir -p /etc/rancher/rke2
[ -e /etc/rancher/rke2/config.yaml ] || cat <<EOF > /etc/rancher/rke2/config.yaml
token: ${TOKEN}
tls-san:
 - ${SYSTEMURL}
resolv-conf: /etc/resolv-ipv4.conf
service-node-port-range: 0-65535
EOF

cat <<'EOF' >> .nodesh.tmp
curl -sfL https://get.rke2.io | sh -
systemctl enable rke2-server.service
systemctl start rke2-server.service

echo 'PATH=/var/lib/rancher/rke2/bin/:${PATH}' >> .profile

cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
EOF
fi

cat <<'EOF' >> .nodesh.tmp
chmod 600 /root/.kube/config
snap install kubectl --classic
EOF

cat <<'EOF' >> .nodesh.tmp
if [ ! -e /.swap.tmp ]; then
dd if=/dev/zero bs=1024 count=$[1024*1024*2] of=/.swap.tmp
echo "/.swap.tmp swap swap defaults 0 0" >> /etc/fstab
mkswap /.swap.tmp
fi
swapon -a
EOF

for NODE in ${NODES};do
	if [ "${NODE}" = "$(hostname -s)" ]; then
		mkdir -p /etc/rancher/rke2/

		cp .nodesh.tmp /root/install-node.sh
		chmod +x /root/install-node.sh && /root/install-node.sh

		### Kube Tools
		snap install kubeadm --classic
		snap install kustomize

		### Other Tools
		apt-get -y install argon2 apache2-utils

		### VPN
		apt-get -y install wireguard wireguard-tools qrencode

		if [ "${ENGINE}" = "rke2" ]; then
			echo "server: https://${SYSTEMURL}:9345" > conf/rke2-node.yaml
			cat /etc/rancher/rke2/config.yaml >> conf/rke2-node.yaml
		fi
		kubectl taint node ${NODE} CriticalAddonsOnly=:NoSchedule
		kubectl label node ${NODE} node.longhorn.io/create-default-disk=config
		kubectl annotate node ${NODE} node.longhorn.io/default-disks-config='[{"name":"data2-longhorn-'${NODE}'","path":"/data2/longhorn","allowScheduling":true,"storageReserved":0}]'
	else
		ssh -p ${SSHPORT} root@${NODE}.${DOMAIN} "mkdir -p /etc/rancher/rke2/"
		[ "${ENGINE}" = "rke2" ] && scp -P ${SSHPORT} conf/rke2-node.yaml root@${NODE}.${DOMAIN}:/etc/rancher/rke2/config.yaml
		[ "${ENGINE}" = "microk8s" ] && scp -P ${SSHPORT} conf/microk8s-node.yaml root@${NODE}.${DOMAIN}:/etc/microk8s.yaml
		scp -P ${SSHPORT} /etc/resolv-ipv4.conf root@${NODE}.${DOMAIN}:/etc/resolv-ipv4.conf
		scp -P ${SSHPORT} .nodesh.tmp root@${NODE}.${DOMAIN}:/root/install-node.sh
		ssh -p ${SSHPORT} root@${NODE}.${DOMAIN} "chmod +x /root/install-node.sh && /root/install-node.sh"
		kubectl label node ${NODE} node.longhorn.io/create-default-disk=config
		kubectl annotate node ${NODE} node.longhorn.io/default-disks-config='[{"name":"data2-longhorn-'${NODE}'","path":"/data2/longhorn","allowScheduling":true,"storageReserved":0}]'
	fi
done

snap install helm --classic
## Cert-Manager is mandatory
helm repo add jetstack https://charts.jetstack.io
helm repo update
kubectl create namespace cert-manager
kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true
helm upgrade --install=true cert-manager jetstack/cert-manager \
	--namespace cert-manager --create-namespace \
	--set crds.enabled=true \
	--set crds.keep=true

### Our customization
## Certificates
kubectl apply -f conf/cert-manager-all.yaml

cat <<'EOF'|kubectl apply -f -
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tls-wildcard
  namespace: cert-manager
spec:
  secretName: tls-wildcard
  issuerRef:
    name: dns
    kind: ClusterIssuer
    group: cert-manager.io
  commonName: "${SYSTEMURL}"
  dnsNames:
    - "${SYSTEMURL}"
    - "*.${DOMAIN}"
    - "*.apps.${DOMAIN}"
    - "*.dev.${DOMAIN}"
EOF

## RKE2
if [ "${ENGINE}" = "rke2" ]; then
## Ingress
kubectl create cm -n kube-system udp-services
cat <<'EOF'|kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: tcp-services
  namespace: kube-system
data:
  "2222": gitlab/gitlab-gitlab-shell:22
  "5000": registry/registry:5000
EOF

cat <<'EOF' > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml
---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-ingress-nginx
  namespace: kube-system
spec:
  valuesContent: |-
    controller:
      tolerations:
      - effect: NoSchedule
        key: CriticalAddonsOnly
        operator: Exists
      extraArgs:
        tcp-services-configmap: $(POD_NAMESPACE)/tcp-services
        udp-services-configmap: $(POD_NAMESPACE)/udp-services
        default-ssl-certificate: cert-manager/tls-wildcard
      config:
        force-ssl-redirect: "true"
        use-forwarded-headers: "true"
        enable-real-ip: "true"
        proxy-add-original-uri-header: "true"
        log-format-escape-json: "true"
        map-hash-bucket-size: "128"
        proxy-body-size: 150M
        use-geoip2: "true"
        proxy-set-headers: ingress-nginx/custom-headers
      containerPort:
        http: 80
        https: 443
        ssh: 2222
        registry: 5000
#     metrics:
#       enabled: true
#       serviceMonitor:
#         enabled: true
EOF
fi

### Rancher
#REPO=stable
REPO=latest

helm repo add rancher-${REPO} https://releases.rancher.com/server-charts/${REPO}
helm repo update
kubectl create namespace cattle-system
helm upgrade --install=true rancher rancher-${REPO}/rancher \
	--namespace cattle-system \
	--set replicas=1 \
	--set hostname=${SYSTEMURL} \
	--set tls=external \
	--disable=rke2-snapshot-controller,rke2-snapshot-controller-crd,rke2-snapshot-validation-webhook \
	--set ingress.extraAnnotations.'cert-manager\.io/cluster-issuer'=letsencrypt

# Wait until ready
until kubectl get secret --namespace cattle-system bootstrap-secret 2> /dev/null;do sleep 4;done
echo https://${SYSTEMURL}/dashboard/?setup=$(kubectl get secret --namespace cattle-system bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}')

### LongHorn
helm repo add longhorn https://charts.longhorn.io
helm repo update
kubectl create namespace longhorn-system
helm upgrade --install=true longhorn longhorn/longhorn \
        --namespace longhorn-system \
	--values conf/longhorn-values.yaml
kubectl apply -f conf/storageclass-longhorn-rwx.yaml
