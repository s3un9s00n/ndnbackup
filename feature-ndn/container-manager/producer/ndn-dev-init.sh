#!/bin/bash

base_container_name="ndn_producer"
base_container='cpd9957/named_data_networking:0.1'

container_count=2

router_ip="192.168.0.97"

base_container_name="ndn_producer"

command_container_volume="-v $(pwd):/usr/src/app"
command_consumer_container_port_=("-p 6363:6363/tcp -p 6363:6363/udp" "-p 6364:6363/tcp -p 6364:6363/udp")

echo "[*] Start !!!!!!"
echo "[*] Create container"

for (( i = 0; i <= $container_number; i++ )); do
  command_create_container="docker run -d --name ${base_container_name}_$i ${command_container_volume} ${command_consumer_container_port_[$i]} ${base_container}"
  command command_create_container
done

sleep 3

echo "[*] NFDC FACE"
for (( i = 0; i < $container_count; i++ )); do
    command docker exec "${base_container_name}_$i" $
done

cmd_exec_in_container="nfdc face create udp4://${router_ip}:${consumer_container_port_[0]}"
docker exec "${base_container_name}_2" ${cmd_exec_in_container}

cmd_exec_in_container="nfdc face create udp4://${router_ip}:${consumer_container_port_[1]}"
docker exec "${base_container_name}_2" ${cmd_exec_in_container}
