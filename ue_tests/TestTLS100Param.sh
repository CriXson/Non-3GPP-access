#!/bin/bash

ue_addr=${ue_addr:-"$1"}
ue_port=${ue_port:-"8102"}
scheme=${scheme:-"http"}
auth_method=${auth_method:-"EAP_TLS"}
n3iwf_address=${n3iwf_address:-"10.45.0.1"}
supi_or_suci=${supi_or_suci:-"0100f110000000000000000110"}
k=${k:-"465B5CE8B199B49FAA5F0A2EE238A6BC"}
opc_type=${opc_type:-"OPC"}
opc=${opc:-"E8ED289DEBA952E4283B54E88E6183CA"}
ike_bind_addr=${ike_bind_addr:-"10.0.2.$2"}
servingNetworkName=${servingNetworkName:-"5G:mnc001.mcc001.3gppnetwork.org"}
attackVariant=${attackVariant:-"TestTLS100"}
while [ $# -gt 0 ]; do
   if [[ $1 == *"--"* ]]; then
        param="${1/--/}"
        declare $param="$2"
   fi
  shift
done
sucis=("0100f110000000000000000110" "0100f110000000000000010110" "0100f110000000000001010110" "0100f110000000000101010110" "0100f110000000001101010110" "0100f110000000000000110110" "0100f110000000000001110110" "0100f110000000000011110110" "0100f110000000000111110110" "0100f110000000000110110110")
total_values=${#sucis[@]}
for i in {1..1000}
do
  index=$((i % total_values))
  declare supi_or_suci=${sucis[$index]}
  echo ${sucis[$index]}
  echo "In iteration $i SUPI: $supi_or_suci"

  gnome-terminal  -- bash -c "sudo timeout 30 ../bin/ue_both_ec $ue_addr;"
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