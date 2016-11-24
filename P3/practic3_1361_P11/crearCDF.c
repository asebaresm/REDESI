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

int main(int argc, char *argv[]){
	crearCDF(argv[1],"salida.txt");
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

	//printf("%s", filename_data);
	leer = fopen(filename_data, "r");
	escribir = fopen(filename_cdf, "w");


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
	leer = fopen(filename_data, "r");
	while(fgets(datos, 255, leer)){
		strcpy(aux,datos);
		cad = strtok(datos, " ");
		porc = (atof(cad) / (double)num_lines);
		result += porc;
	    cad = strtok(NULL, " \n");
		fprintf(escribir, "%s %.5f\n", cad, result);
	}
	fclose(leer);

	return OK;
}
