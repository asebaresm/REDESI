/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira
 2015 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN) /* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1

#define IP_ALEN      4      /* Tamanio de la direccion IP           */
#define IP_HLEN      20     /* Tamanio de la cabecera IP            */
#define IP_VER       1      /* Tamanio de la version IP            */
#define IP_LON		 2 		/* Tamanio del campo longitud IP*/
#define IP_POS		 2		/* Tamanio del campo posicion IP en bits*/
#define IP_TVID		 1  	/* Tamanio del campo tiempo vida IP*/
#define IP_PROT   	 1  	/* Tamanio del campo protocolo IP*/
#define IP_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define IP_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define IP_DATA_MAX  (IP_FRAME_MAX - IP_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define IP_DATA_MIN  (IP_FRAME_MIN - IP_HLEN) /* Tamanio de la direccion IP					*/

#define TPT_ALEN     2      /* Tamanio de la direccion TCP           */
#define TPT_HLEN      36     /* Tamanio de la cabecera TCP            */
#define TPT_TLEN      4      /* Tamanio de la version TCP en bits            */
#define TPT_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define TPT_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define TPT_DATA_MAX  (TPT_FRAME_MAX - TPT_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define TPT_DATA_MIN  (TPT_FRAME_MIN - TPT_HLEN) /* Tamanio de la direccion TCP	*/

#define UDP_ALEN     4      /* Tamanio de la direccion UDP           */
#define UDP_HLEN      24     /* Tamanio de la cabecera UDP            */
#define UDP_LON		 2 		/* Tamanio del campo longitud UDP*/
#define UDP_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define UDP_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define UDP_DATA_MAX  (UDP_FRAME_MAX - UDP_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define UDP_DATA_MIN  (UDP_FRAME_MIN - UDP_HLEN) /* Tamanio de la direccion UDP						*/

//#define DEBUG
#ifdef DEBUG
	#define DEBUG_PRINT(x) printf x
#else
	#define DEBUG_PRINT(x) do {} while (0)
#endif

void analizar_paquete(const struct pcap_pkthdr *cabecera, const uint8_t *paquete);

void handleSignal(int nsignal);

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipo_filtro[IP_ALEN] = {0};
uint8_t ipd_filtro[IP_ALEN] = {0};
uint16_t po_filtro = 0;
uint16_t pd_filtro = 0;
int tamIHL = 0;
int proto = 0;

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv)
{
	uint8_t *paquete = NULL;
	struct pcap_pkthdr *cabecera;

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index = 0, retorno = 0;
	char opt;
	
	(void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			/*printf("Descomente el código para leer y abrir de una interfaz\n");
			exit(ERROR);*/
			
			/*if ( (descr = ??(optarg, ??, ??, ??, errbuf)) == NULL){
				printf("Error: ??(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}*/
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			/*printf("Descomente el código para leer y abrir una traza pcap\n");
			exit(ERROR);*/

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipo_filtro[0]), &(ipo_filtro[1]), &(ipo_filtro[2]), &(ipo_filtro[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipd_filtro[0]), &(ipd_filtro[1]), &(ipd_filtro[2]), &(ipd_filtro[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((po_filtro = atoi(optarg)) == 0) {
				printf("Error o_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((pd_filtro = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	//if(ipo_filtro[0]!=0)
	printf("ipo_filtro:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipo_filtro[0], ipo_filtro[1], ipo_filtro[2], ipo_filtro[3]);
	//if(ipd_filtro[0]!=0)
	printf("ipd_filtro:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipd_filtro[0], ipd_filtro[1], ipd_filtro[2], ipd_filtro[3]);

	if (po_filtro != 0) {
		printf("po_filtro=%"PRIu16"\t", po_filtro);
	}   

	if (pd_filtro != 0) {
		printf("pd_filtro=%"PRIu16"\t", pd_filtro);
	}
	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &cabecera, (const u_char **)&paquete);

		if (retorno == 1) { //Tó correcto
			contador++;
			analizar_paquete(cabecera, paquete);
		
		} else if (retorno == -1) { //En caso de error
			printf("Error al capturar un paquete %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
			pcap_close(descr);
			exit(ERROR);

		}
	} while (retorno != -2);

	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(const struct pcap_pkthdr *cabecera, const uint8_t *paquete)
{
	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (cabecera->ts.tv_sec)));

	int i = 0;

	printf("Direccion ETH destino= ");
	printf("%02X", paquete[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", paquete[i]);
	}

	printf("\n");
	paquete += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", paquete[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", paquete[i]);
	}

	printf("\n");

	paquete+=ETH_ALEN + 2; //Inicio Paquete IP
	uint8_t aux = 0;
	uint16_t pos = 0;
	//uint8_t pos = 0;
	memcpy(&aux, &paquete[0], sizeof(uint8_t));
	
	/*printf("PAQUETE2");
	printf("%02X\n", aux);
	printf("DESPLAZAMIENTO2");
	printf("%02X\n", paquete[0]);*/
	aux = (paquete[0]>>4);

	printf("Version = ");
	printf("%d\n", aux);

	memcpy(&aux, &paquete[0], sizeof(uint8_t));
	aux = aux << 4;
	aux = aux >> 4;
	tamIHL = aux *(32/8);
	//printf("Tamano IHL %d\n",tamIHL);
	DEBUG_PRINT(("Tamano IHL %d\n",tamIHL));

	paquete+= IP_VER +1;
	printf("Longitud Total IP = ");
	printf("%d", paquete[0]);
	for (i = 1; i < IP_LON; i++) {
		printf(".%d", paquete[i]);
	}

	paquete+= IP_LON + 2;
	printf("\n");
	
	memcpy(&aux, &paquete[0], sizeof(uint8_t));
	
	/*aux = aux|(cero << 5);
	aux = aux|(cero << 6);
	aux = aux|(cero << 7);
	*/
	aux = aux << 3;
	aux = aux >> 3;
	memcpy(&pos, &aux, sizeof(uint16_t));
	pos = pos << 8;
	pos = pos|paquete[1];
	printf("Posicion IP = ");
	if(pos != 0){ /*cambio jueves 20*/
		printf("El paquete IP leido no es el primer fragmento\n");
	}else{
		/*aux = 0;
		aux = (paquete[0]<<13);*/
		printf("%d\n", pos);
		//int pac = 0;
		paquete+= IP_POS;
		printf("Tiempo de vida = ");
		printf("%d\n", paquete[0]);
		paquete+= IP_TVID;
		printf("Protocolo = ");
		printf("%d\n", paquete[0]);


        if (paquete[0] == 6){
            proto = 6;
        }else if (paquete[0] == 17){
            proto = 17;
        } else{
            proto = paquete[0];
        }

		if(paquete[0] == 6 || paquete[0] == 17){
			
			paquete+= 3;

			printf("Direccion IP origen = ");
			printf("%d", paquete[0]);

			for (i = 1; i < IP_ALEN; i++){
				printf(".%d", paquete[i]);
			}
			printf("\n");
			paquete+= IP_ALEN;

			printf("Direccion IP destino = ");
			printf("%d", paquete[0]);

			for (i = 1; i < IP_ALEN; i++){
				printf(".%d", paquete[i]);
			}

			paquete += 4 + (tamIHL-IP_HLEN); //NUMERO_MAGICO
            /*END NIVEL 3*/
            /*EMPIEZA NIVEL 4 - YA ES TCP/UDP*/
            DEBUG_PRINT(("\n__NIVEL 4__"));
            if (proto == 6){        //TCP
                printf("\nProtocolo TCP");
                printf("\nDireccion origen: ");
                for(i=0; i<TPT_ALEN; i++){
                    printf("%d", paquete[i]);
                }
                paquete += TPT_ALEN;
                printf("\nDireccion destino: ");
                for(i=0; i<TPT_ALEN; i++) {
                    printf("%d", paquete[i]);
                }
            }else if(proto == 17){  //UDP
                printf("\nProtocolo UDP");
                printf("\nDireccion origen: ");
                for(i=0; i<UDP_ALEN; i++){
                    printf("%d", paquete[i]);
                }
                paquete += UDP_ALEN;
                printf("\nDireccion destino: ");
                for(i=0; i<UDP_ALEN; i++) {
                    printf("%d", paquete[i]);
                }
                paquete += UDP_ALEN;
                printf("\nLongitud:");
                for(i=0; i<UDP_ALEN; i++) {
                    printf("%d.", paquete[i]);
                }
            }else{                  //NISMO

            }
			//for (i = 0; i < IP_LON; i++) {
				//aux = paquete[i];
				//pac = paquete[i];
				//printf(":%d", pos[]);
				/*sprintf(posicion, aux, paquete[0]);

				printf(":%d", atoi(posicion));*/
			//}
			//insertar 3 ceros derecha y luego 3 ceros izquierda
			/*int versionIp;
			versionIp = paquete[0];
			printf("%d", paquete[0]);
			for(i = 0; i < paquete[0]; i++){
				if(versionIp < 10){
					break;
				}
				versionIp = versionIp -10;
			}*/
			/*
			for (i = 1; i < 1; i++) {
				printf(":%d", paquete[i]);
			}*/
		}else{
			printf("Protocolo no esperado");
		}
	}
	printf("\n");
	// .....
	// .....
	// .....

	printf("\n\n");
}
