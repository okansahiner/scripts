#!/bin/bash

key="$1"

wget --no-check-certificate https://IP.IP/ks/conf/physical/prod/post6.sh -O /root/post_install.sh
chmod 744 /root/post_install.sh



case $key in
    --firsttime-prod)
	nohup /root/post_install.sh --firsttime-prod >> /root/post_install.log 2>&1
    ;;
    --firsttime-test)
	nohup /root/post_install.sh --firsttime-test >> /root/post_install.log 2>&1
    ;;
    *)
        echo -e "No parameter given..."
    ;;
esac
