#!/bin/bash

base_container_name="ndn_consumer"

sub_name_path="/logos"

docker exec ${base_container_name}_2 ndnping ${sub_name_path}