#include <stdint.h>
#include <Windows.h>
#include <stdio.h>
#include "trap.h"

uint8_t len;
uint8_t packet[] = { 0 };

void s(uint8_t* buff, uint8_t *length) {
	const char* IP = "127.0.0.1";
	const u_short PORT = 162;
	WSADATA wsdata;
	SOCKET SendRecvSocket;
	SOCKADDR_IN SendAddr;

	WSAStartup(0x0101, &wsdata);

	SendRecvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	SendAddr.sin_family = AF_INET;
	SendAddr.sin_addr.s_addr = inet_addr(IP);
	SendAddr.sin_port = htons(PORT);
	sendto(SendRecvSocket, buff, *length, 0, (SOCKADDR*)& SendAddr, *length);
}

int main(int argc, char** argv) {
	uint8_t val = atoi(argv[1]);

	selectSendingValue(val);
	sendSNMPTrap(&packet, &len);
	printf("%d", len);
	s(&packet, &len);

	return 0;
}