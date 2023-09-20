#!/bin/bash

ue_addr=${ue_addr:-"10.0.2.15"}
ue_port=${ue_port:-"8102"}
scheme=${scheme:-"http"}
auth_method=${auth_method:-"5G_AKA"}
n3iwf_address=${n3iwf_address:-"10.45.0.1"}
supi_or_suci=${supi_or_suci:-"001010000000001"}
k=${k:-"465B5CE8B199B49FAA5F0A2EE238A6BC"}
opc_type=${opc_type:-"OPC"}
opc=${opc:-"E8ED289DEBA952E4283B54E88E6183CA"}
ike_bind_addr=${ike_bind_addr:-"10.0.2.15"}
servingNetworkName=${servingNetworkName:-"5G:mnc001.mcc001.3gppnetwork.org"}
attackVariant=${attackVariant:-"Test5GAKA100"}
while [ $# -gt 0 ]; do
   if [[ $1 == *"--"* ]]; then
        param="${1/--/}"
        declare $param="$2"
   fi
  shift
done
sucis=("001010000011101" "001010000000001" "001010000001101" "001010000000011" "001010000011111" "001010000011110" "001010000011100" "001010000011000" "001010000010000" "001010000101000")

total_values=${#sucis[@]}
for i in {1..200}
do
  index=$((i % total_values))
  declare supi_or_suci=${sucis[$index]}
  echo ${sucis[$index]}
  echo "In iteration $i SUPI: $supi_or_suci"

  gnome-terminal  -- bash -c "timeout 30 sudo ../bin/ue_both_ec;"
  echo "sleeping for 1 seconds after starting ue"
  sleep 1
  curl --insecure --location --request POST "$scheme://$ue_addr:$ue_port/registration/" \
  --header 'Content-Type: application/json' \
  --data-raw "{
      \"authenticationMethod\": \"$auth_method\",
      \"supiOrSuci\": \"$supi_or_suci\",
      \"K\": \"$k\",
      \"opcType\": \"$opc_type\",
    \"opc\": \"$opc\",
    \"plmnId\": \"\",
    \"servingNetworkName\": \"$servingNetworkName\",
      \"n3IWFIpAddress\": \"$n3iwf_address\",
      \"ikeBindAddress\": \"$ike_bind_addr\",
      \"SNssai\": {
          \"Sst\": 1,
          \"Sd\": \"010203\"
      },
      \"attackVariant\": \"$attackVariant\"
  }"
  echo "Waiting 6 second before next request"
  sleep 6

done