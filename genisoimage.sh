#!/bin/bash

# https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Installation_Guide/s1-kickstart2-putkickstarthere.html

# STEPS

# mkdir /mnt/iso
# mkdir /var/www/html/ks/scripts/temp
# mount -o loop /var/www/html/ks/6.7/isos/path_RHEL6.7_auto.iso /mnt/iso
# cp -pRf /mnt/iso /var/www/html/ks/scripts/temp
# umount /mnt/iso
# rm -rf /mnt/iso


# make changes

cd temp/iso

genisoimage -U -r -v -T -J -joliet-long -V "RHEL-6.7" -volset "RHEL-6.7" -A "RHEL-6.7" -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e images/efiboot.img -no-emul-boot -o ../../path_RHEL6.7_auto_new.iso .

# rm -rf temp
