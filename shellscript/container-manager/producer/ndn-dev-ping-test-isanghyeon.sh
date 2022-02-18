#!/bin/bash

base_container_name="ndn_producer"

prefix_name_path="/isanghyeon"

docker exec ${base_container_name}_1 ndnpingserver ${prefix_name_path}