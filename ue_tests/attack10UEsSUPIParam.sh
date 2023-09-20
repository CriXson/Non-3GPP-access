#!/bin/bash

interface="enp0s3"  # Network interface name
ip_base="10.0.2."  # Base IP address



start_ip=15  # Starting IP address
end_ip=24 # Ending IP address
sucis=("0100f110000000000000000110" "0100f110000000000000010110" "0100f110000000000001010110" "0100f110000000000101010110" "0100f110000000001101010110" "0100f110000000000000110110" "0100f110000000000001110110" "0100f110000000000011110110" "0100f110000000000111110110" "0100f110000000000110110110")
sucisAKA=("001010000011101" "001010000000001" "001010000001101" "001010000000011" "001010000011111" "001010000011110" "001010000011100" "001010000011000" "001010000010000" "001010000101000")
total_values=${#sucis[@]}

for ((i=start_ip; i<=end_ip; i++)); do
  index=$((i % total_values))
  declare supi_or_suci=${sucis[$index]}
  echo ${sucis[$index]}
  echo "In iteration $i SUPI: $supi_or_suci"
  ip_address="$ip_base$i"
  sudo ip addr add "$ip_address/24" dev "$interface"
  echo $ip_address $i
  gnome-terminal  -- bash -c "sudo ../trigger_initial_registration_param.sh $ip_address $i $supi_or_suci"
  sleep 5
done


