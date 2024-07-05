#!/bin/bash

/bin/nmap -sV $ip -p 22 | grep OpenSSH | awk '{print $5 }'
