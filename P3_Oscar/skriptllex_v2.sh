#!bin/bash

#===============================================================================================
#DOCUMENTACION
#===============================================================================================
#Sobre divisiones de resultados de otros comandos:
#	(1)	http://unix.stackexchange.com/questions/24035/how-to-calculate-values-in-a-shell-script
#	(2)	http://stackoverflow.com/questions/12147040/division-in-script-and-floating-point
#
#Colores *-*
#	(1) https://linuxtidbits.wordpress.com/2008/08/11/output-color-on-bash-scripts/
#
#Sobre display filters (y capture filters):
#	https://wiki.wireshark.org/DisplayFilters
#
#
#Notacion de display filters:
#Comparison operators					|	Logical expressions		
#eq, ==    Equal						|	and, &&   Logical AND
#ne, !=    Not Equal					|	or,  ||   Logical OR
#gt, >     Greater than					|	not, !    Logical NOT
#lt, <     Less Than					|	
#ge, >=    Greater than or Equal to		|	
#le, <=    Less than or Equal to		|	
#
#Series con X granularidad:
#	traza.pcap -qz io,stat,1,"eth" NO VA, EQUIVALENTE A traza.pcap -qz io,stat,1,"not(not eth)"
#
#Sobre 'awk script embedding in a bash script':
#	http://www.linuxtopia.org/online_books/advanced_bash_scripting_guide/wrapper.html
#
#
#==============================================================================================
#EJECUCION
#==============================================================================================

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

#Ficheros para luego filtrar
echo "\n${green}Generando ficheros...${reset}"

#
#if [ ! -f ips.out ]; then
#	tshark -r traza.pcap -T fields -e ip.src > ips.out
#	tshark -r traza.pcap -T fields -e ip.dst >> ips.out
#fi

#Para top ips (apariciones)+ top ips (bytes)
#fichero (ip.src primero y despues ip.dst concatenado): ip | frame.len
if [ ! -f ips_framelen.out ]; then
	tshark -r traza.pcap -T fields -e ip.src -e frame.len -Y 'ip' > ips_framelen.out
	tshark -r traza.pcap -T fields -e ip.dst -e frame.len -Y 'ip' >> ips_framelen.out
fi

#Counts
echo "${green}Filtrando paquetes...${reset}"
count_todos=$(tshark -r traza.pcap -Y 'eth' | wc -l)
count_eth_ip=$(tshark -r traza.pcap -Y '(eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800' | wc -l)
count_eth_NO_ip=$(tshark -r traza.pcap -Y '!((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800)' | wc -l)
count_tcp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && tcp' | wc -l)
count_udp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && udp' | wc -l)
count_others=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && !(tcp || udp)' | wc -l)

top_ips_paquetes=$(awk -F"\t" '{print $1}' ips_framelen.out | sort | uniq -c | sort -rn | head -n 10)

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

echo "\nTops:"

echo "Direcciones IP más activas en ${blu}número de paquetes${reset}: "
echo "$top_ips_paquetes"

echo "\nDirecciones IP más activas en ${blu}número de bytes${reset}: "
#tshark -r traza.pcap -T fields -e ip.src -e ip.dst -e frame.len -Y 'ip' > todos.out
filtered_count=$(wc -l < ips_framelen.out)

echo "Generando Estadisticas -------------------------------->"

tshark -r traza.pcap -T fields -e frame.len -Y eth.src==00:11:88:CC:33:1B | sort -n -r | uniq -c | sort -n -k 2 > eth_src.txt
#uniq -c eth_src.txt > eth_src_ord.txt
#sort -n -k 2 eth_src_ord.txt > eth_ord_src_cnt.txt

tshark -r traza.pcap -T fields -e frame.len -Y eth.dst==00:11:88:CC:33:1B | sort -n -r | uniq -c | sort -n -k 2 > eth_dst.txt
#uniq -c eth_dst.txt > eth_dst_ord.txt
#sort -n -k 2 eth_dst_ord.txt > eth_ord_dst_cnt.txt

tshark -r traza.pcap -T fields -e frame.len -Y '(eth.addr==00:11:88:CC:33:1B && tcp.dstport==80)' | sort -n -r | uniq -c | sort -n -k 2 > tcp_dst.txt

tshark -r traza.pcap -T fields -e frame.len -Y '(eth.addr==00:11:88:CC:33:1B && tcp.srcport==80)' | sort -n -r | uniq -c | sort -n -k 2 > tcp_src.txt

tshark -r traza.pcap -T fields -e frame.len -Y '(eth.addr==00:11:88:CC:33:1B && udp.dstport==53)' | sort -n -r | uniq -c | sort -n -k 2 > udp_dst.txt

tshark -r traza.pcap -T fields -e frame.len -Y '(eth.addr==00:11:88:CC:33:1B && udp.srcport==53)' | sort -n -r | uniq -c | sort -n -k 2 > udp_src.txt

tshark -r traza.pcap -T fields -e frame.time_delta -Y '(eth.addr==00:11:88:CC:33:1B && ip.addr==37.246.132.71)' | sort -n -r | uniq -c | sort -n -k 2 > tcp_time.txt

tshark -r traza.pcap -T fields -e frame.time_delta -Y '(eth.addr==00:11:88:CC:33:1B && ip.dst==37.246.132.71 && ip.proto==6)' | sort -n -r | uniq -c | sort -n -k 2 > tcp_dst_time.txt

tshark -r traza.pcap -T fields -e frame.time_delta -Y '(eth.addr==00:11:88:CC:33:1B && ip.src==37.246.132.71 && ip.proto==6)' | sort -n -r | uniq -c | sort -n -k 2 > tcp_src_time.txt

tshark -r traza.pcap -T fields -e frame.time_delta -Y '(eth.addr==00:11:88:CC:33:1B && ip.proto==17 && udp.dstport==54189)' | sort -n -r | uniq -c | sort -n -k 2 > udp_dst_time.txt

tshark -r traza.pcap -T fields -e frame.time_delta -Y '(eth.addr==00:11:88:CC:33:1B && ip.proto==17 && udp.srcport==54189)' | sort -n -r | uniq -c | sort -n -k 2 > udp_src_time.txt
#BEGIN awk script
#--------------------------------
#awk_func=$(
#awk '
#BEGIN {
#	FS = "\t";
#}
# {
#	suma_valores[$1] = suma_valores[$1] + $2;
#}
#END{
	#for(valor in suma_valores){
#		print suma_valores[valor]" \t"valor;
#	}
#}
#' "ips_framelen.out" | sort -rn | head -n 10
#)
#"ips_framelen.out" > "top_ips.out"
#sort -rn "top_ips.out"| head -n 10
#--------------------------------
#END  awk script
#echo "$awk_func"


