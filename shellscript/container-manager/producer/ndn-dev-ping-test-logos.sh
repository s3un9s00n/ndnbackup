#!/bin/bash

base_container_name="ndn_producer"

sub_name_path="/logos"

docker exec ${base_container_name}_2 ndnpingserver ${sub_name_path}