#!/bin/bash

base_container_name="ndn_consumer"

prefix_name_path="/isanghyeon"

docker exec ${base_container_name}_1 ndnping ${prefix_name_path}