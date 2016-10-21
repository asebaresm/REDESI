cmake_minimum_required(VERSION 3.6)
project(P1)

#Mirar Makefile
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

set(SOURCE_FILES practica2.c)
add_executable(P2 ${SOURCE_FILES})

#Ejecucion: ./<ejecutable> -f <nombre .pcap>