#!/bin/bash

base_container_name="ndn_consumer"
base_container='cpd9957/named_data_networking:0.1'

container_volume="$(pwd):/usr/src/app"

router_ip="10.211.55.13"

prefix_name_path="/isanghyeon"
sub_name_path="/logos"

consumer_container_tcp_=("6363:6363/tcp" "6364:6363/tcp")
consumer_container_udp_=("6363:6363/udp" "6364:6363/udp")
consumer_container_port_=("6363" "6364")

echo "[*] Start !!!!!!"
echo "[*] Create container"
docker run -d --name "${base_container_name}_1" -v "${container_volume}" -p "${consumer_container_tcp_[0]}" -p "${consumer_container_udp_[0]}" ${base_container}
docker run -d --name "${base_container_name}_2" -v "${container_volume}" -p "${consumer_container_tcp_[1]}" -p "${consumer_container_udp_[1]}" ${base_container}

sleep 3

echo "[*] NFDC FACE"
cmd_exec_in_container="nfdc face create udp4://${router_ip}:${consumer_container_port_[0]}"
docker exec "${base_container_name}_1" ${cmd_exec_in_container}

cmd_exec_in_container="nfdc face create udp4://${router_ip}:${consumer_container_port_[1]}"
docker exec "${base_container_name}_2" ${cmd_exec_in_container}

sleep 3

echo "[*] NFDC ROUTE"
cmd_exec_in_container_prefix_name="nfdc route add ${prefix_name_path} udp4://${router_ip}:${consumer_container_port_[0]}"
docker exec "${base_container_name}_1" ${cmd_exec_in_container_prefix_name}

cmd_exec_in_container_sub_name="nfdc route add ${sub_name_path} udp4://${router_ip}:${consumer_container_port_[1]}"
docker exec "${base_container_name}_2" ${cmd_exec_in_container_sub_name}