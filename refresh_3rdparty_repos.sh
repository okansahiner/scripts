#!/bin/bash

reposync -n -c /etc/yum.conf -p /var/www/html/ks/3rd_Party/vmware/ -d -r vmware-tools-rhel6; createrepo /var/www/html/ks/3rd_Party/vmware/vmware-tools-rhel6/
reposync -n -c /etc/yum.conf -p /var/www/html/ks/3rd_Party/vmware/ -d -r vmware-tools-rhel7; createrepo /var/www/html/ks/3rd_Party/vmware/vmware-tools-rhel7/
createrepo /var/www/html/ks/3rd_Party/emc/rhel6/
createrepo /var/www/html/ks/3rd_Party/emc/rhel7/
createrepo /var/www/html/ks/3rd_Party/custom/rhel6/
createrepo /var/www/html/ks/3rd_Party/custom/rhel7/
