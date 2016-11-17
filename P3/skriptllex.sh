#!bin/bash

#============================================================================================
#DOCUMENTACION
#============================================================================================
#Sobre divisiones de resultados de otros comandos:
#	(1)	http://unix.stackexchange.com/questions/24035/how-to-calculate-values-in-a-shell-script
#	(2)	http://stackoverflow.com/questions/12147040/division-in-script-and-floating-point
#
#============================================================================================
#EJCUCION
#============================================================================================

echo "\n============Porcentajes de paquetes============"

#TODOS los paquetes
echo "Volcando todos los paquetes a fichero..."
#tshark -r traza.pcap -T text -V > todos_paquetes.txt
if [ ! -f todos_paquetes.out ]; then
    tshark -r traza.pcap -Y 'eth' >> todos_paquetes.out
fi

#Paquetes que son ETH|VLAN|IP
echo "Filtrando paquetes ETH|VLAN|IP..."
#Paquetes que son ETH|IP
echo "Filtrando paquetes que son ETH|IP..."
if [ ! -f eth_ip.out ]; then
    tshark -r traza.pcap -Y 'eth.type==0x8100 && vlan.etype==0x0800' > eth_ip.out
    tshark -r traza.pcap -Y 'eth.type==0x8100' >> eth_ip.out
fi

#Paquetes que NO son ETH|VLAN|IP
echo "Filtrando paquetes que NO son ETH|VLAN|IP..."
#Paquetes que NO son ETH|VLAN
echo "Filtrando paquetes que NO son ETH|VLAN..."
if [ ! -f eth_NO_ip.out ]; then
    tshark -r traza.pcap -Y 'eth.type==0x8100 && !vlan.etype==0x0800' > eth_NO_ip.out
    tshark -r traza.pcap -Y '!eth.type==0x8100' >> eth_NO_ip.out
fi

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

echo "\nPorcentaje paquetes IP:"
# $((100*($count_eth_ip/$count_todos)))
#let a=count_eth_ip/count_todos
div=$(echo "scale=2; $count_eth_ip/$count_todos" | bc)
res=$(echo "scale=2; $div*100" | bc)
echo "$res"%

