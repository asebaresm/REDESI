#!bin/bash

#============================================================================================
#VARIABLES
#============================================================================================

#============================================================================================
#EEJCUCION
#============================================================================================

echo "\n============Porcentajes de paquetes============\n"

#TODOS los paquetes
echo "\nVolcando todos los paquetes a fichero..."
#tshark -r traza.pcap -T text -V > todos_paquetes.txt
tshark -r traza.pcap -Y 'eth' >> todos_paquetes.out

#Paquetes que son ETH|VLAN|IP
echo "\nFiltrando paquetes ETH|VLAN|IP..."
tshark -r traza.pcap -Y 'eth.type==0x8100 && vlan.etype==0x0800' > eth_ip.out

#Paquetes que son ETH|IP
echo "\nFiltrando paquetes que son ETH|IP..."
tshark -r traza.pcap -Y 'eth.type==0x8100' >> eth_ip.out

#Paquetes que NO son ETH|VLAN|IP
echo "\nFiltrando paquetes que NO son ETH|VLAN|IP..."
tshark -r traza.pcap -Y 'eth.type==0x8100 && !vlan.etype==0x0800' > eth_NO_ip.out

#Paquetes que NO son ETH|VLAN
echo "\nFiltrando paquetes que NO son ETH|VLAN..."
tshark -r traza.pcap -Y '!eth.type==0x8100' >> eth_NO_ip.out


#count=$let ( ($count_todos + $count_eth_ip)/$count_todos))
#porcentaje_IP=$((count_eth_ip/count_todos))
#porcentaje_IP=$(expr 100*(count_eth_ip /count_todos))
#Counts
count_todos=$(wc -l < todos_paquetes.out)
count_eth_ip=$(wc -l < eth_ip.out)
count_eth_NO_ip=$(wc -l < eth_NO_ip.out)

echo "$count_todos"
echo "$count_eth_ip"
echo "$count_eth_NO_ip"

echo "\nPorcentaje paquetes IP:\n"
echo "$((100*($count_eth_ip/$count_todos)))"

