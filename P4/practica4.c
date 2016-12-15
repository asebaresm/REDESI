/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

	FILE *f=NULL;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					//Leer fichero en data
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					printf("\n Fichero:  %s \n",optarg);
					f = fopen(optarg,"rb");
					if(f == NULL){
						printf("\n Error en fopen \n");
						return ERROR;
						
					}
					fread(data,sizeof(uint8_t),IP_DATAGRAM_MAX,f);
					fclose(f);
				}
				flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.puerto_destino=puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,pila_protocolos,strlen(data),&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Luego, un paquete ICMP en concreto un ping
	
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping",pila_protocolos,strlen("Probando a hacer un ping"),&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);
	
		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,pila_protocolos,longitud,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0,suma_control=0x00;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	uint16_t longitud_total=0;
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	//Comprobar la longitud
	if (longitud>(pow(2,16)-UDP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;


	if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		printf("Error: En la funcion obtenerPuertoOrigen en moduloUDP\n");
		return ERROR;
	}
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Escribir el puerto destino
	aux16=htons(puerto_destino);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Escribir la longitud
	//Longitud total es cabecera UDP + mensaje
	longitud_total = longitud + UDP_HLEN;
	aux16=htons(longitud_total);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Escribir suma de control o check sum (siempre 0 por simplcidad en UDP)
	memcpy(segmento+pos,&suma_control,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//Escribir los datos
	memcpy(segmento+pos,mensaje,longitud);


//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	//mostrarPaquete(segmento, pos+longitud) ;
	return protocolos_registrados[protocolo_inferior](segmento,pila_protocolos,longitud+pos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint8_t datagrama2[IP_DATAGRAM_MAX]={0};

	uint32_t aux32;
	uint16_t aux16;
	uint8_t aux8;

	uint32_t pos=0,pos_control=0,posChecksum = 0, posChecksumInicial=0, posFragmentacion=0, posDatosAux=0;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];

	uint8_t checksum[2], uno=1;
	int i = 0;
	int flagSubred=1;
	uint16_t MTU=0, tam_data = 0, numPaquetesFrag = 0, mascaraPosicion=0, offset_aux=0;

	uint8_t gateway[IP_ALEN];

	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;

	//Comprobar longitud
	if (longitud>pow(2,16)){
		printf("Error: mensaje demasiado grande para IP (%f).\n",pow(2,16));
		return ERROR;
	}

	//Construir la cabecera IP
		aux8=0x45; 
	//aux8|0x45
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	//Tipo de servicio
	//Todo 0
	aux8=0x00;
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	//longitud total 
	//Longitud total = longitud del segmento mas cabecera
	aux16 = htons(longitud + 20); //!!! tamaño cabecera
	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Identificacion
	//identifiacion 0 en fragmentados cambiara
	aux16=htons(ID);
	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Flags y posicion 0 en fragmentaos cambiara
	aux16=0x0000;
	posFragmentacion = pos;
	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Tiempo de vida
	//Ponemos un numero muy grande
	aux8=0xFF;
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	//Protocolo
	aux8 = protocolo_superior;
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	//Suma de control 
	//Ponemos a 0 y luego llamamos a la funcion de cehcksum
	//Ponemos checksum 
	aux16=0;
	pos_control=pos;
	posChecksumInicial=pos;
	memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	//Obtener direccion de origen
	if(obtenerIPInterface(interface,IP_origen) == ERROR){
		printf("Error: En la funcion obtenerIPInterface en moduloIP\n");
		return ERROR;
	}
	memcpy(datagrama+pos,IP_origen,IP_ALEN);
	pos += IP_ALEN;

	//Obtenemos mascara de la interfaz
	if(obtenerMascaraInterface(interface, mascara) == ERROR){
		printf("Error: Al obtener mascara interface\n");
		return ERROR;
	}

	//Aplicamos mascara IP_rango_origen
	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) != OK){
		printf("Error: Al aplicar mascara\n");
		return ERROR;
	}

	//Aplicamos mascara IP_rango_destino
	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) != OK){
		printf("Error: Al aplicar mascara\n");
		return ERROR;
	}

	//Distinguimos entre subred o no subred
	for(i=0;i<IP_ALEN;i++){
		if(IP_rango_origen[i] != IP_rango_destino[i])
			flagSubred = 0;
	}

	//Caso flagSubred=1 realizamos el salto (estamos en la subred)
	//Caso flagSubred=0 obtenemos la ip del router
	if (flagSubred != 0) {
		if(ARPrequest(interface, IP_destino, ipdatos.ETH_destino) == ERROR){
			printf("Error: En el ARP request\n");
			return ERROR;
		}
	}else{
		if(obtenerGateway(interface, gateway) == ERROR){
			printf("Error: En al obtener gateway\n");
			return ERROR;
		}
		if (ARPrequest(interface, gateway, ipdatos.ETH_destino) == ERROR){
			printf("Error: En el ARP request\n");
			return ERROR;
		}
	}

	//Obtenemos la IP destino
	printf("\n\nIP: %u.%u.%u.%u\n",IP_destino[0],IP_destino[1],IP_destino[2],IP_destino[3]);
	memcpy(datagrama + pos, IP_destino, IP_ALEN);
	pos += IP_ALEN;
	//Guadamos la posicion checksum
	posChecksum=pos;
	//Llamar al checksum
	if(calcularChecksum(pos,datagrama,checksum) == ERROR){
		printf("Error: En la funcion calcularChecksum en moduloIP\n");
		return ERROR;
	}

	//Copiamos un nuevo datagrama para el caso en que sea necesrio fragmentar
	memcpy(datagrama2 + pos_control, checksum, CHECKSUM_SIZE);
	memcpy(datagrama2, datagrama, pos);

	/*Segmento*/
	posDatosAux = pos;
	memcpy(datagrama+pos, segmento, longitud);
	pos +=longitud; //..asi esta en pos la pos + longitud

	/*Obtenemos la MTU*/
	if (obtenerMTUInterface(interface, &MTU) == ERROR) {
		printf("Error: en la funcion obtenerMTUInterface\n");
		return ERROR;
	}
	/*Una vez obtenida la MUT, calcular el tamaño de los datos
	por fragmento*/	
	//MTU - cabecera
	tam_data = MTU - 20;
	//Calcular el numero total de paquetes resultantes de la fragmentacion
	numPaquetesFrag = (longitud + tam_data - 1) / tam_data;

	for(i = 0; i < numPaquetesFrag; i++){
		/*Flags de posicion */
		//0x3FFF = 001111...11
		mascaraPosicion = offset_aux & 0x3FFF;
		mascaraPosicion = mascaraPosicion >> 3;

		//Comprobar si es el último paquete
		if(i+1 == numPaquetesFrag){
			tam_data = longitud;
			mascaraPosicion = ntohs(mascaraPosicion);
		}else{ //no lo es
			mascaraPosicion = ntohs(mascaraPosicion | (uno << 13));
		}

		/*copiarlo*/
		memcpy(datagrama2+posFragmentacion, &mascaraPosicion,sizeof(uint16_t));

		/*Insertar el offset*/
		//tam data + cabecera
		aux16 = htons(tam_data + 20);
		memcpy(datagrama2+2,&aux16,sizeof(uint16_t));

		/*Calcular e insertar el uevo checksum*/
		aux16=0x0000;
		memcpy(datagrama2+posChecksumInicial,&aux16,sizeof(uint16_t));

		if (calcularChecksum(posChecksum, datagrama2, checksum) == ERROR) {
			printf("Error: calcularChecksum en moduloIP\n");
			return ERROR;
		}
		//Copiarlo  (checksum)
		memcpy(datagrama2+posChecksumInicial, checksum, CHECKSUM_SIZE);

		//Copiar los datos al fragmento
		memcpy(datagrama2+posDatosAux,segmento,tam_data);
		segmento=segmento+tam_data;

		//Enviarlo a ETH
		if (protocolos_registrados[protocolo_inferior](datagrama2,pila_protocolos,tam_data + 20,&ipdatos) == ERROR)
		{
			printf("Error: en protocolos_registrados moduloIP\n");
			return ERROR;
		}

		offset_aux=offset_aux + tam_data;
		longitud = longitud - tam_data;
	}

	return OK;
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
//Variables del modulo
	uint8_t trama[ETH_FRAME_MAX]={0};

	uint16_t aux16;
	struct pcap_pkthdr cabeceraPcap;
	uint32_t pos=0;
	uint8_t ETH_origen[ETH_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];	

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

//Control de tamano
	if (longitud>pow(2,16)){
		printf("Error: mensaje demasiado grande para ETH (%f).\n",pow(2,16));
		return ERROR;
	}
//Cabecera del modulo
	Parametros ethdatos=*((Parametros*)parametros);

	//Direccion ETH destino
	memcpy(trama+pos,ethdatos.ETH_destino,ETH_ALEN);
	pos+=ETH_ALEN;

	//Direccion ETH origen
	if(obtenerMACdeInterface(interface,ETH_origen) == ERROR){
		printf("Error: En la funcion obtenerMACdeInterface en moduloETH\n");
		return ERROR;
	}
	memcpy(trama+pos,ETH_origen,ETH_ALEN);
	pos+=ETH_ALEN;
	//Tipo Ethernet
	aux16=htons(protocolo_superior);
	memcpy(trama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copiamos a la trama*/
	memcpy(trama+pos,datagrama,longitud);

//Enviar a capa fisica [...]
	//PROVISIONAL PARA PRUEBAS: cambiar porque es un 0
	//https://linux.die.net/man/3/pcap_sendpacket
	if(pcap_sendpacket(descr,trama,pos+longitud) == -1){
		printf("Error: En pcap_sendpacket en moduloETH\n");
		return ERROR;
	}

//Almacenamos la salida por cuestiones de debugging [...]
	//Mostramos el paquete
	mostrarPaquete(trama, pos + longitud);

	cabeceraPcap.len = pos + longitud;
	cabeceraPcap.caplen = cabeceraPcap.len;
	gettimeofday(&cabeceraPcap.ts, NULL);	
	pcap_dump((uint8_t *)pdumper,&cabeceraPcap,trama);
	
	return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint16_t* pila_protocolos,uint64_t longitud,void *parametros){
	uint8_t foo_ret = 0;

	uint8_t segmento[UDP_SEG_MAX]={0};
	uint8_t tipo = 8;
	uint8_t codigo = 0;
	uint8_t aux8;
	uint8_t checksum[2];
	uint8_t id = rand();
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];

	//Comprobar la longitud
	if (longitud>(pow(2,16)-UDP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros icmpdatos=*((Parametros*)parametros);

	aux8=htons(tipo);
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	aux8=htons(codigo);
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/*if(calcularChecksum(longitud + pos + 6, segmento ,checksum) == ERROR){
		printf("Error: En la funcion calcularChecksum en moduloIP\n");
		return ERROR;
	}	*/
	
	memcpy(segmento+pos,&aux8, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Escribir el puerto destino
	aux16=htons(id);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	aux16=htons(1);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	
	if(calcularChecksum(longitud + pos, segmento ,checksum) == ERROR){
		printf("Error: En la funcion calcularChecksum en moduloIP\n");
		return ERROR;
	}	
	memcpy(segmento+ 2 ,checksum,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	return protocolos_registrados[protocolo_inferior](segmento,pila_protocolos,longitud+pos,parametros);
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
//TODO
//[...]
    int i = 0;

    //AND de bit a bit
    for (i=0;i<longitud;i++) {
        resultado[i] = IP[i] & mascara[i];
    }

    return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados) == ERROR)
		return ERROR;
	
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR; 
	
	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


