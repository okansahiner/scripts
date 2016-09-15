#!/bin/bash

KERNEL_IMG=$(ls /boot/vmlinuz-$(uname -r))
INITRAMFS_IMG=$(ls /boot/initramfs-$(uname -r).img)
CMD_PARAMS=$(cat /proc/cmdline)


echo "running kernel image  :  ${KERNEL_IMG}"
echo "running initramfs     :  ${INITRAMFS_IMG}" 
echo "loaded params         :  ${CMD_PARAMS}"
echo -e "\nwill be executed      :  \nkexec -l ${KERNEL_IMG} --initrd=${INITRAMFS_IMG} --append=${CMD_PARAMS}" 

kexec -l ${KERNEL_IMG} --initrd=${INITRAMFS_IMG} --append="${CMD_PARAMS}"


echo -e "\nkexec reboot executed...\n"

kexec -e




