/***********************************************************
 crearCDF.c	 
 Primeros pasos para implementar y validar la funcion crearCDF(). Est funcion debe devolver
 un fichero con dos columnas, la primera las muestras, la segunda de distribucion de
 probabilidad acumulada. En la version actual la funcion realiza los dos primeros pasos para
 este objetivo, cuenta el numero de muestras y las ordena.
 El alumno debe acabar su implementacion de crearCDF() y usar un main similar para validar su fucionamiento.
 
 Compila: gcc -Wall -o crearCDF crearCDF.c
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM 
***************************************************************************/

#include <stdio.h> 
#include <stdlib.h> 
#include <strings.h> 
#include <string.h> 

#define OK 0
#define ERROR 1

int crearCDF(char* filename_data, char* filename_cdf);

int main(){
	crearCDF("udp_dst_time.txt","salida.txt");
	return OK;
}

int crearCDF(char* filename_data, char* filename_cdf) {
	/*char comando[255]; char linea[255]; */char aux[255]; char datos[255];
	int num_lines;
	char * cad;
	//FILE *f;
	FILE * leer;
	FILE * escribir;
	double porc;
	double result;
//sin control errores
	//sprintf(comando,"wc -l %s 2>&1",filename_data); //wc cuenta lineas acabadas por /n
	//printf("Comando en ejecucion: %s\n",comando);
	leer = fopen("udp_dst_time.txt", "r");
	escribir = fopen("salida.txt", "w");
	//f = popen(comando, "r");
	//leer = fopen("ejemplo.txt", "r");
	//if(f == NULL){
	//	printf("Error ejecutando el comando\n");
	//	return ERROR;
	//}
	/*fgets(linea,255,f);
	printf("Retorno: %s\n",linea);
	sscanf(linea,"%d %s",&num_lines,aux);
	pclose(f);*/

	if(leer == NULL){
		printf("Error leyendo el comando\n");
		return ERROR;
	}

	num_lines =0;
	while(fgets(datos, 255, leer)){
		cad = strtok(datos, " ");
		num_lines += atoi(cad);
	}

	fclose(leer);
	leer = fopen("udp_dst_time.txt", "r");
	while(fgets(datos, 255, leer)){
		strcpy(aux,datos);
		printf("%s\n", aux);
		cad = strtok(datos, " ");
		porc = (atof(cad) / (double)num_lines);
		result += porc;
	    cad = strtok(NULL, " \n");
	    printf(" %s", cad);
		fprintf(escribir, "%s %.5f\n", cad, result);
	}

	/*sprintf(comando,"sort -n < %s > %s 2>&1",filename_data,filename_cdf);
	printf("Comando en ejecucion: %s\n",comando);*/
	//f = popen(comando, "r");
	/*if(f == NULL){
		printf("Error ejecutando el comando\n");
		return ERROR;
	}*/
	//bzero(linea,255);
	//fgets(linea,255,f);
	//printf("Retorno: %s\n",linea);
	//pclose(f);

//crear CDF

	return OK;
}



