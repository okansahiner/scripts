#!/bin/bash

############

INIT_HOSTNAME=kube01
IP=192.168.122.20

###########
DOMAIN_NAME=example.com
INIT_FQDN=${INIT_HOSTNAME}.${DOMAIN_NAME}
NMASK=255.255.255.0
GW=192.168.122.1
NS1=8.8.8.8
CPUS=2
MEM=512
#############

DIR=~/Folders/kvm-vms/${INIT_HOSTNAME}
IMAGE=~/Folders/kvm-vms/centos7tmp/CentOS-7-x86_64-GenericCloud-1708.qcow2
USER_DATA=user-data
META_DATA=meta-data
CI_ISO=${INIT_HOSTNAME}-init.iso
DISK=${DIR}/${INIT_HOSTNAME}_root.qcow2
BRIDGE=virbr0


virsh dominfo ${INIT_HOSTNAME} > /dev/null 2>&1
if [ "$?" -eq 0 ]; then
    echo -n "[WARNING] ${INIT_HOSTNAME} already exists.  "
    read -p "Do you want to overwrite ${INIT_HOSTNAME} [y/N]? " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
    else
        echo -e "\nNot overwriting ${INIT_HOSTNAME}. Exiting..."
        exit 1
    fi
fi

rm -rf $DIR
mkdir -p $DIR
touch ${DIR}/${INIT_HOSTNAME}.log

pushd $DIR > /dev/null

    echo "$(date -R) Destroying the ${INIT_HOSTNAME} domain (if it exists)..."
    virsh destroy ${INIT_HOSTNAME} >> ${INIT_HOSTNAME}.log 2>&1
    virsh undefine ${INIT_HOSTNAME} >> ${INIT_HOSTNAME}.log 2>&1

    cat > $USER_DATA << _EOF_
#cloud-config
preserve_hostname: False
hostname: ${INIT_HOSTNAME}
fqdn: ${INIT_FQDN}
ssh_pwauth: True
disable_root: false
chpasswd:
  list: |
    root:123456
  expire: false

write_files:
  - path: /etc/sysconfig/network-scripts/ifcfg-eth0
    content: |
      BOOTPROTO=none
      DEVICE=eth0
      IPADDR=${IP}
      NETMASK=255.255.255.0
      GATEWAY=${GW}
      DNS1=${NS1}
      DOMAIN=${DOMAIN_NAME}
      ONBOOT=yes
      TYPE=Ethernet
      USERCTL=no

runcmd:
  - [ ifdown, eth0 ]
  - [ ifup, eth0 ]
  - [ yum, -y, remove, cloud-init ]
output: 
  all: ">> /var/log/cloud-init.log"


_EOF_

    cat > $META_DATA << _EOF_
instance-id: ${INIT_HOSTNAME}
local-hostname: ${INIT_HOSTNAME}
_EOF_

    echo "$(date -R) Copying template image..."
    cp -v $IMAGE $DISK

    echo "$(date -R) Generating ISO for cloud-init..."
    genisoimage -output $CI_ISO -volid cidata -joliet -r $USER_DATA $META_DATA &>> ${INIT_HOSTNAME}.log

    echo "$(date -R) Installing the domain and adjusting the configuration..."
    echo "[INFO] Installing with the following parameters:"
    echo "virt-install --import --name ${INIT_HOSTNAME} --ram $MEM --vcpus $CPUS --disk
    $DISK,format=qcow2,bus=virtio --disk $CI_ISO,device=cdrom --network
    bridge=virbr0,model=virtio --os-type=linux --os-variant=rhel6 --noautoconsole"

    virt-install --import --name ${INIT_HOSTNAME} --ram $MEM --vcpus $CPUS --disk \
    $DISK,format=qcow2,bus=virtio --disk $CI_ISO,device=cdrom --network \
    bridge=virbr0,model=virtio --os-type=linux --os-variant=rhel6 --noautoconsole

    echo "$(date -R) Cleaning up cloud-init..."
    virsh change-media ${INIT_HOSTNAME} hda --eject --config >> ${INIT_HOSTNAME}.log

    rm $CI_ISO

    echo "$(date -R) DONE. SSH to ${INIT_HOSTNAME} using $IP, with user root pass 123456."

popd > /dev/null
