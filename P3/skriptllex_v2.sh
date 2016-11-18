#!bin/bash

#============================================================================================
#DOCUMENTACION
#============================================================================================
#Sobre divisiones de resultados de otros comandos:
#	(1)	http://unix.stackexchange.com/questions/24035/how-to-calculate-values-in-a-shell-script
#	(2)	http://stackoverflow.com/questions/12147040/division-in-script-and-floating-point
#
#Colores *-*
#	(1) https://linuxtidbits.wordpress.com/2008/08/11/output-color-on-bash-scripts/
#
#
#============================================================================================
#EJECUCION
#============================================================================================

red=`tput setaf 1`
green=`tput setaf 2`
blu=`tput setaf 4`
reset=`tput sgr0`

if [ ! -f traza.pcap ]; then
    echo "\nERROR: no se ha encontrado la traza .pcap"
    exit 1
fi


clear
echo "\n============${blu}Porcentajes de paquetes${reset}============"

#TODOS los paquetes
#echo "Volcando todos los paquetes a fichero..."
#tshark -r traza.pcap -T text -V > todos_paquetes.txt
#if [ ! -f todos_paquetes.out ]; then
#    tshark -r traza.pcap -Y 'eth' >> todos_paquetes.out
#fi

echo "\n${green}Filtrando paquetes...${reset}"

#Counts
count_todos=$(tshark -r traza.pcap -Y 'eth' | wc -l)
count_eth_ip=$(tshark -r traza.pcap -Y '(eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800' | wc -l)
count_eth_NO_ip=$(tshark -r traza.pcap -Y '!((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800)' | wc -l)
count_tcp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && tcp' | wc -l)
count_udp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && udp' | wc -l)
count_others=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && !(tcp || udp)' | wc -l)


echo "\nEn total:\t\t $count_todos"
echo "IP:\t\t\t $count_eth_ip"
echo "NO IP:\t\t\t $count_eth_NO_ip"
echo "TCP:\t\t\t $count_tcp"
echo "UDP:\t\t\t $count_udp"
echo "Other:\t\t\t $count_others"

#div=$(echo "scale=2; $count_eth_ip/$count_todos" | bc)
#res=$(echo "scale=2; $div*100" | bc)
#echo "$res"%

#3 formas de hacerlo:
#div=$(echo "scale=6; 100*$count_eth_ip/$count_todos" | bc )
#div=$(echo "scale=6; 100*$count_eth_ip/$count_todos" | bc | awk '{printf "%f", $0}')
div=$(echo "scale=6; x=100*$count_eth_ip/$count_todos; if(x<1) print 0; x" | bc )
echo "\nPorcentaje paquetes ${blu}ETH|IP${reset} ó ${blu}ETH|VLAN|IP${reset}:\t\t$div%"

#div=$(echo "scale=6; 100*$count_eth_NO_ip/$count_todos" | bc)
#div=$(echo "scale=6; 100*$count_eth_NO_ip/$count_todos" | bc | awk '{printf "%f", $0}')
div=$(echo "scale=6; x=100*$count_eth_NO_ip/$count_todos; if(x<1) print 0; x" | bc )
echo "Porcentaje paquetes ${blu}NOT (ETH|IP ó ETH|VLAN|IP)${reset}:\t\t$div%"

div=$(echo "scale=6; x=100*$count_tcp/$count_eth_ip; if(x<1) print 0; x" | bc )
echo "Porcentaje paquetes ${blu}TCP${reset} sobre IP:\t\t\t$div%"

div=$(echo "scale=6; x=100*$count_udp/$count_eth_ip; if(x<1) print 0; x" | bc )
echo "Porcentaje paquetes ${blu}UDP${reset} sobre IP:\t\t\t$div%"

div=$(echo "scale=6; x=100*$count_others/$count_eth_ip; if(x<1) print 0; x" | bc )
echo "Porcentaje paquetes ${blu}otro${reset} tipo sobre IP:\t\t\t$div%"