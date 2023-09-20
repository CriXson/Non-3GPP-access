#!/bin/bash

ue_addr=${ue_addr:-"$1"}
ue_port=${ue_port:-"8102"}
scheme=${scheme:-"http"}
auth_method=${auth_method:-"EAP_TLS"}
n3iwf_address=${n3iwf_address:-"10.45.0.1"}
supi_or_suci=${supi_or_suci:-"$3"}
k=${k:-"465B5CE8B199B49FAA5F0A2EE238A6BC"}
opc_type=${opc_type:-"OPC"}
opc=${opc:-"E8ED289DEBA952E4283B54E88E6183CA"}
ike_bind_addr=${ike_bind_addr:-"10.0.0.$2"}
servingNetworkName=${servingNetworkName:-"5G:mnc001.mcc001.3gppnetwork.org"}
attackVariant=${attackVariant:-"InitialUE"}

while [ $# -gt 0 ]; do
   if [[ $1 == *"--"* ]]; then
        param="${1/--/}"
        declare $param="$2"
   fi
  shift
done
echo $3
echo $supi_or_suci

for i in {1..1000}
do
  echo "Iteration $i"
  gnome-terminal  -- bash -c "sudo timeout 30 ../bin/ue_both_rsa $ue_addr"
  echo "sleeping for 1 seconds after starting ue"
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

  echo "Waiting 60 second before next request"
done