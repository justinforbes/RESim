#!/usr/bin/bash
mkdir -p logs/driver
#ssh -p 4022 mike@localhost "journalctl -u start_driver_service.service >/tmp/driver_service.log"
ssh -p 4022 mike@localhost "journalctl -u start_dhcp.service >/tmp/dhcp.log"
ssh -p 4022 mike@localhost "journalctl -u start_dns.service >/tmp/dns.log"
scp -P 4022 mike@localhost:/tmp/*.log logs/driver/
