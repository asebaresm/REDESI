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
#	(1) http://www.linuxtopia.org/online_books/advanced_bash_scripting_guide/wrapper.html
#
#	(2) Pillar la N columna de un fichero:
#			http://stackoverflow.com/questions/11668621/how-to-get-the-first-column-of-every-line-from-a-csv-file
#	(3) http://stackoverflow.com/questions/28087461/awk-print-is-not-working-inside-bash-shell-script
#	(4) Entrelazando shell + awk:
#			https://www.cyberciti.biz/faq/bash-scripting-using-awk/
#
#Sobre 'python embedding in bash scripts':
#	(1) http://bhfsteve.blogspot.com.es/2014/07/embedding-python-in-bash-scripts.html
#
#
#==============================================================================================
#EJECUCION
#==============================================================================================

red=`tput setaf 1`
green=`tput setaf 2`
blu=`tput setaf 4`
reset=`tput sgr0`

clear
printf "====================${blu}Script de analisis${reset}===================="

if [ ! -f traza.pcap ]; then
    echo "\nERROR: no se ha encontrado la traza .pcap"
    exit 1
fi

#TODOS los paquetes
#echo "Volcando todos los paquetes a fichero..."
#tshark -r traza.pcap -T text -V > todos_paquetes.txt
#if [ ! -f todos_paquetes.out ]; then
#    tshark -r traza.pcap -Y 'eth' >> todos_paquetes.out
#fi

#Ficheros para luego filtrar
echo "\n${green}Generando ficheros...${reset}"
printf "[${green}                         ${reset}](0%%)\r"
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
printf "[${green}#############            ${reset}](50%%)\r"

if [ ! -f port_framelen.out ]; then
	tshark -r traza.pcap -T fields -e tcp.srcport -e frame.len -Y 'ip.proto==6' > port_framelen.out
	tshark -r traza.pcap -T fields -e tcp.dstport -e frame.len -Y 'ip.proto==6' >> port_framelen.out
	tshark -r traza.pcap -T fields -e udp.srcport -e frame.len -Y 'ip.proto==17' >> port_framelen.out
	tshark -r traza.pcap -T fields -e udp.srcport -e frame.len -Y 'ip.proto==17' >> port_framelen.out
fi
printf "[${green}#########################${reset}](100%%)\r"
printf "\n"

#Counts
echo "${green}Filtrando paquetes...${reset}"
printf "[${green}                         ${reset}](0%%)\r"
count_todos=$(tshark -r traza.pcap -Y 'eth' | wc -l)
count_eth_ip=$(tshark -r traza.pcap -Y '(eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800' | wc -l)
printf "[${green}#####                    ${reset}](20%%)\r"
count_eth_NO_ip=$(tshark -r traza.pcap -Y '!((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800)' | wc -l)
printf "[${green}##########               ${reset}](40%%)\r"
count_tcp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && tcp' | wc -l)
printf "[${green}###############          ${reset}](60%%)\r"
count_udp=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && udp' | wc -l)
printf "[${green}####################     ${reset}](80%%)\r"
count_others=$(tshark -r traza.pcap -Y '((eth.type==0x8100 && vlan.etype==0x0800) || eth.type==0x0800) && !(tcp || udp)' | wc -l)
printf "[${green}#########################${reset}](100%%)\r"

echo "\n\nEn total:\t\t $count_todos"
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

echo "Direcciones IP más activas en ${blu}número de paquetes${reset}:"
top_ips_paquetes=$(awk -F"\t" '{print $1}' ips_framelen.out | sort | uniq -c | sort -rn | head -n 10)
echo "$top_ips_paquetes"

echo "\nDirecciones IP más activas en ${blu}número de bytes${reset}: "
#tshark -r traza.pcap -T fields -e ip.src -e ip.dst -e frame.len -Y 'ip' > todos.out
filtered_count=$(wc -l < ips_framelen.out)

#BEGIN awk script 1
#--------------------------------
awk_func=$(
awk '
BEGIN {
	FS = "\t";
}
{
	suma_valores[$1] = suma_valores[$1] + $2;
}
END{
	for(valor in suma_valores){
		print suma_valores[valor]" \t"valor;
	}
}
' "ips_framelen.out" | sort -rn | head -n 10
)
#--------------------------------
#END  awk script 1
echo "$awk_func"

echo "\nPuertos más activos en ${blu}número de paquetes${reset}: "
top_puertos_paquetes=$(awk -F"\t" '{print $1}' port_framelen.out | sort | uniq -c | sort -rn | head -n 10)
echo "$top_puertos_paquetes"

echo "\nPuertos más activos en ${blu}número de bytes${reset}: "
#BEGIN awk script 2
#--------------------------------
awk_func=$(
awk '
BEGIN {
	FS = "\t";
}
{
	suma_valores[$1] = suma_valores[$1] + $2;
}
END{
	for(valor in suma_valores){
		print suma_valores[valor]" \t"valor;
	}
}
' "port_framelen.out" | sort -rn | head -n 10
)
#--------------------------------
#END  awk script 2
echo "$awk_func"


