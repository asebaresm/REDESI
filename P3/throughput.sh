#!bin/bash

#function procesaTabla {
procesaTabla() {
python - << EOF
import sys
import csv

f = open('throughput.out','r')
#saltarse la cabecera de la tabla y ultima linea
line_list = f.readlines()[11:-1]
#quitar ruido
line_list[:] = [x.replace('\n', '').replace('\r', '').replace(' ','') for x in line_list]

table = []
for line in line_list:
    table.append(line.split('|'))

for row in table:
    del row[0]
    del row[1]
    del row[1]
    del row[3]
    del row[3]
for row in table:
    #que hacer con row[0]
    row[1] = int(row[1])
    row[2] = int(row[2])

with open('throughput.txt', 'w') as csvfile:
    writer = csv.writer(csvfile, delimiter=' ')
    [writer.writerow(r) for r in table]
EOF
}

#call
procesaTabla

gnuplot -persist <<-EOFMarker
	set term png
	set output "Graficas/thoughput.png"
	set title "Throughput" font ",14" textcolor rgbcolor "royalblue"
	set xlabel "intervalo (s)"
	set ylabel "bytes"
	plot "throughput.txt" using 1:3 with lines title "Datos"
EOFMarker