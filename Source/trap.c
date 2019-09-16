#include <stdint.h>
#include <Windows.h>
#include <stdio.h>
#include "trap.h"

uint8_t len;
uint8_t* packet;

void formSNMPTrap(uint8_t val) {
	#pragma region Values
	uint8_t snmp_message[] = { 0x30, 0x3A }; //0x30 - Sequence 0x3A - Length
	uint8_t pdu_type[] = { 0xa7, 0x2D }; //SNMP PDU(0xa7 - Snmpv2, 0x2D - Length)// TrapV2c
	uint8_t comm_string[] = { 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63 }; //Community String(0x04-String, 0x06-ID)//public
	uint8_t version[] = { 0x02, 0x01, 0x01 }; //Version(0x02-Integer, 0x01 - Object ID)//1
	uint8_t request_id[] = { 0x02, 0x01, 0x1 }; //RequestID(0x02 - Integer 0x01 - Length  0x01 - Value) //1
	uint8_t error_status[] = { 0x02, 0x01, 0x00 }; //ErrorStatus(0x00 - Type 0x02 - Integer 0x00 - Index)
	uint8_t error_index[] = { 0x02, 0x01, 0x00 };//ErrorIndex(If an Error occurs, otherwise the Error Index is 0x00)
	uint8_t var_list[] = { 0x30, 0x22 };//VarList(0x30 - Sequence Length - 0x22)
	uint8_t var_bind[] = { 0x30, 0x10 };//VarBind(0x30-Sequence Length - 0x10)
	uint8_t var_bindT[] = { 0x30, 0xE };// VarBind(0x30-Sequence Length - 0xE)
	uint8_t oid[] = { 0x06, 0x0b, 0x2b, 0x06,0x01, 0x04, 0x01, 0x82, 0xe7, 0x68, 0x01, 0x05, 0x01 }; //OID (0x06 - ObjID 0x0b - Length)
	uint8_t value[] = { 0x02, 0x01, 0x01 };//Value
	uint8_t sysUpTime[] = { 0x43, 0x02, 0x13, 0x3 };
	uint8_t timetick_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00 };//TimeTick OID
	#pragma endregion
	value[2] = val == 0 ? 0x00 : 0x01;
	#pragma region SnmpTRAP
	uint8_t packet_bytes[] = {
		snmp_message[0], snmp_message[1], version[0], version[1], version[2], comm_string[0], comm_string[1], comm_string[2],
		comm_string[3],comm_string[4], comm_string[5], comm_string[6], comm_string[7], pdu_type[0], pdu_type[1],
		request_id[0], request_id[1], request_id[2], error_status[0], error_status[1], error_status[2],
		error_index[0],error_index[1], error_index[2], var_list[0], var_list[1], var_bind[0], var_bind[1],
		oid[0], oid[1], oid[2], oid[3], oid[4], oid[5],oid[6], oid[7], oid[8], oid[9], oid[10], oid[11], oid[12],
		value[0], value[1], value[2], var_bindT[0], var_bindT[1],
		timetick_oid[0], timetick_oid[1], timetick_oid[2], timetick_oid[3], timetick_oid[4], timetick_oid[5], timetick_oid[6],
		timetick_oid[7], timetick_oid[8], timetick_oid[9], sysUpTime[0], sysUpTime[1], sysUpTime[2], sysUpTime[3]
	};
	#pragma endregion
	uint8_t length = (uint8_t)(sizeof(packet_bytes) / sizeof(packet_bytes[0]));
	len = length;
	packet = malloc(len * sizeof(uint8_t));
	if (packet != 0) {
		memcpy(packet, packet_bytes, len);
	}
}


void sendSNMPTrap(uint8_t* out_buf, uint8_t* length) {
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

	uint8_t size = (uint8_t)*length;
	sendto(SendRecvSocket, out_buf, size, 0, (SOCKADDR*)& SendAddr, size);
}


int main(int argc, char** argv) {
	uint8_t val = atoi(argv[1]);
	formSNMPTrap(val);
	uint8_t* l = &len;
	sendSNMPTrap(packet, l);

	return 0;
}