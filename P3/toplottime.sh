#!bin/bash

gnuplot -persist <<-EOFMarker

	set term dumb	

	set title "$2"

	set xlabel "$3"

	set ylabel "$4"

	set logscale x
	set logscale y
	set term jpeg
	set output "Graficas/$1.jpeg"
	plot "salida.txt" using 1:2 with steps title "$5"

	
	replot

	exit
EOFMarker
