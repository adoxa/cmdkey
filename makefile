# MinGW32 makefile for CMDkey.

CC = gcc
CFLAGS = -Wall -O2

all: edit.dll cmdkey.exe cmdkeynt.exe

edit.dll: edit.c
	$(CC) $(CFLAGS) edit.c -mdll -s -o edit.dll -lcomdlg32 \
			-Wl,--out-implib,edit.lib

cmdkey.exe: cmdkey.c
	$(CC) $(CFLAGS) cmdkey.c -s -o cmdkey.exe edit.lib

cmdkeynt.exe: cmdkey.c
	$(CC) $(CFLAGS) -DNT4 cmdkey.c -s -o cmdkeynt.exe edit.lib
