// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: Predmetni Projekat
// ================================================================

/*
Bojan Strbac RA82/2015
*/

// Include libraries

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define HAVE_STRUCT_TIMESPEC
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#include "file_manipulation.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>

pcap_t* device_handle;
unsigned char* packet_data;
pcap_t* eth_handle;
pcap_t* wifi_handle;
char** data_array;
FILE* f;
int number_of_packets = 0;
unsigned char keyString[] = "BokaMare";

unsigned long idZaPrvaDva = 0;
unsigned long idZaEthernet = 0;
unsigned long idZaWiFi = 0;

unsigned long fileSize;
unsigned long sizeOfLast;
pthread_mutex_t myMutex;

/*Functions*/
void init_ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data);
void sendFirstTwoPackets(unsigned char* data_ext, unsigned char* packet_data, unsigned char* number_of_elements, int packet_len);
void ack_handler_ethernet(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data);
void ack_handler_wifi(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data);
pcap_if_t* select_device(pcap_if_t* devices);
void *wifiThreadFunction(void *params);
/***********/
int countEthernet = 0;
int countWifi = 0;

int flagEthernetWorks = 1;
int flagWifiWorks = 1;

unsigned long CURRENT_POSITION_OF_ETHERNET_FAILURE;
unsigned long CURRENT_POSITION_OF_WIFI_FAILURE;

int main()
{
	int i;
	int packet_len;
	int size_of_last;
	int ethernet_header_size;
	int device_number;
	int sentBytes;

	pcap_if_t* devices;
	pcap_if_t* ethernet_device;
	pcap_if_t* wifi_device;

	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned char* data_ext = "eva.jpg";
	unsigned char* number_of_elements;

	pthread_t wifiThread;
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	printf("Select first interface(ETHERNET): \n");
	ethernet_device = select_device(devices);
	if (ethernet_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}
	puts("");
	printf("Select second interface(WIFI): \n");
	wifi_device = select_device(devices);
	if (wifi_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/**************************************************************/
	/***** Open ethernet adapter *****/
	if ((eth_handle = pcap_open_live(ethernet_device->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", ethernet_device->name);
		return -1;
	}
	/**************************************************************/
	/***** Open wifi adapter *****/
	if ((wifi_handle = pcap_open_live(wifi_device->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", ethernet_device->name);
		return -1;
	}

	data_array = read_from_file(f, data_array, &number_of_packets, &size_of_last);
	puts("PROCITAO IZ FAJLA");
	sizeOfLast = size_of_last;
	fileSize = (number_of_packets - 1) * DEFAULT_BUFLEN + sizeOfLast;
	puts("");
	number_of_elements = convert_to_char(number_of_packets, &packet_len);
	printf("Total number of packets: %s\n", number_of_elements);
	puts("");
	printf("Sending data extension and number of packets...\n\n");

	pthread_mutex_init(&myMutex, NULL);
	/*Sending name and number of packets*/
	sendFirstTwoPackets(data_ext, packet_data, number_of_elements, packet_len);

	printf("Data extension sent and number of packets sent!\n\n");

	/*Receiving ACK and if necessary sending first two packets again*/
	/*while (pcap_loop(eth_handle, 0, init_ack_handler, NULL) != -2)
	{
		puts("Sending packets again!\n\n");
		sendFirstTwoPackets(data_ext, packet_data, number_of_elements, packet_len);
		Sleep(2);
	}*/

	printf("ACK has been received!\n");
	printf("Sending data...\n");
	puts("");
	puts("***************************************************\n\n");
	puts("***************************************************\n\n");

	/************SENDING HALF OF THE FILE OVER WIFI************/
	pthread_create(&wifiThread, NULL, wifiThreadFunction, NULL);
	/**********************************************************/

	/************SENDING HALF OF THE FILE OVER ETHERNET************/
	for (int i = 0; i < number_of_packets / 2; i++)
	{
		flagEthernetWorks = 1;
		countEthernet = 0;

		puts("SENDING HALF OF THE FILE OVER ETHERNET!");

		pthread_mutex_lock(&myMutex);
		idZaEthernet = i + 3;
		pthread_mutex_unlock(&myMutex);
		printf("\n\nIDDDDD %d\n", i);


		if (i != number_of_packets - 1)
		{
			pthread_mutex_lock(&myMutex);
			packet_data = setup_header_ethernet(data_array[i], packet_data, DEFAULT_BUFLEN, idZaEthernet);
			pthread_mutex_unlock(&myMutex);
			puts("a");
			if (pcap_sendpacket(eth_handle, packet_data, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);
			/*Receive ACK for current packet*/
			puts("D");
			while (pcap_loop(eth_handle, 0, ack_handler_ethernet, NULL) != -2)
			{
				countEthernet++;
				puts("+++");
				puts("Sending packets again!\n\n");
				pcap_sendpacket(eth_handle, packet_data, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE);
				Sleep(2);
				
				if (countEthernet == 500)	//wait ten seconds
				{
					flagEthernetWorks = 0;
					break;
				}

			}
			if (flagEthernetWorks == 0)
			{
				CURRENT_POSITION_OF_ETHERNET_FAILURE = i;
				break;
			}
			puts("c");
		}
		else
		{
			pthread_mutex_lock(&myMutex);
			packet_data = setup_header_ethernet(data_array[i], packet_data, size_of_last, idZaEthernet);
			pthread_mutex_unlock(&myMutex);
			printf("\n*** Size of last: %d ***\n\n", size_of_last + 56);

			if (pcap_sendpacket(eth_handle, packet_data, size_of_last + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);

			/*Receive ACK for current packet*/
			while (pcap_loop(eth_handle, 0, ack_handler_ethernet, NULL) != -2)
			{
				puts("Sending packets again!\n\n");
				pcap_sendpacket(eth_handle, packet_data, size_of_last + TOTAL_HEADER_SIZE);
				Sleep(2);
			}
		}
	}



	pthread_join(wifiThread, NULL);

	printf("D A T A   S E N T!\nTotal number of data packages sent -> %d + first two packets(name and size)\n", number_of_packets);
	puts("");
	free(packet_data);
	free(data_array);
	pcap_close(eth_handle);
	pcap_close(wifi_handle);

	return 0;
}

/******************************************************************************************************************************/
/******************************************************************************************************************************/
/******************************************************************************************************************************/
/******************************************************************************************************************************/

void init_ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data)
{
	ethernet_header * eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("eh %x\n", ntohs(eh->type));
		printf("Not an ip packet!\n");
		return 0;
	}

	ip_header * ih = (ip_header *)(packet_data + sizeof(ethernet_header));


	if (ih->next_protocol != 17)
	{
		printf("ip %d\n", ih->next_protocol);
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * custom_header = packet_data + 42;	//string
	unsigned long num = (*(custom_header + 9) << 32) + (*(custom_header + 10) << 24) + (*(custom_header + 11) << 16) + (*(custom_header + 12) << 8) + *(custom_header + 13);

	if (strcmp(custom_header, keyString) == 0 && num == number_of_packets)
	{
		printf("First two packets (name and size) have been sent!\n\n");
		pcap_breakloop(eth_handle);
	}
}

void sendFirstTwoPackets(unsigned char* data_ext, unsigned char* packet_data, unsigned char* number_of_elements, int packet_len)
{
	for (int i = 0; i < 2; i++)
	{
		pthread_mutex_lock(&myMutex);
		idZaPrvaDva = i + 1;
		pthread_mutex_unlock(&myMutex);
		if (i == 0)
		{
			pthread_mutex_lock(&myMutex);
			packet_data = setup_header_ethernet(data_ext, packet_data, strlen(data_ext) + 1, idZaPrvaDva);
			pthread_mutex_unlock(&myMutex);

			if (pcap_sendpacket(eth_handle, packet_data, strlen(data_ext) + 1 + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				return -1;
			}
			puts("POSLAO PRVI PAKET");
		}
		else
		{
			pthread_mutex_lock(&myMutex);
			packet_data = setup_header_ethernet(number_of_elements, packet_data, strlen(number_of_elements) + 1, idZaPrvaDva);
			pthread_mutex_unlock(&myMutex);

			if (pcap_sendpacket(eth_handle, packet_data, packet_len + TOTAL_HEADER_SIZE) == -1)
			{
				return -1;
			}
			puts("POSLAO DRUGI PAKET");
		}
	}
}

void ack_handler_ethernet(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data)
{
	puts("Entered ethernet ACK!");
	printf("%d\n", idZaEthernet);
	ethernet_header * eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("Not an ip packet!\n");
		return;
	}

	ip_header * ih = (ip_header *)(packet_data + sizeof(ethernet_header));

	printf("%d\n", ih->next_protocol);
	if (ih->next_protocol != 17)
	{
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * custom_header = packet_data + 42;	//string
	unsigned long num = (*(custom_header + 9) << 32) + (*(custom_header + 10) << 24) + (*(custom_header + 11) << 16) + (*(custom_header + 12) << 8) + *(custom_header + 13);

	//pthread_mutex_lock(&myMutex);

	printf("ID of sent packet: %d\n", idZaEthernet);
	printf("Returned ID: %d\n", num);

	if (strcmp(custom_header, keyString) == 0 && num == idZaEthernet)
	{
		Sleep(2);
		puts("Left Ethernet ACK!");
		pcap_breakloop(eth_handle);
	}
	//pthread_mutex_unlock(&myMutex);
}

void ack_handler_wifi(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data)
{
	puts("Entered WiFi ACK!");
	printf("%d\n", idZaWiFi);
	ethernet_header * eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("Not an ip packet!\n");
		return;
	}

	ip_header * ih = (ip_header *)(packet_data + sizeof(ethernet_header));


	if (ih->next_protocol != 17)
	{
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * custom_header = packet_data + 42;	//string
	unsigned long num = (*(custom_header + 9) << 32) + (*(custom_header + 10) << 24) + (*(custom_header + 11) << 16) + (*(custom_header + 12) << 8) + *(custom_header + 13);

	pthread_mutex_lock(&myMutex);

	printf("ID of sent packet: %d\n", idZaWiFi);
	printf("Returned ID: %d\n", num);

	if (strcmp(custom_header, keyString) == 0 && num == idZaWiFi)
	{
		Sleep(2);
		puts("Left WiFi ACK!");
		pcap_breakloop(wifi_handle);
	}
	pthread_mutex_unlock(&myMutex);
}

pcap_if_t* select_device(pcap_if_t* devices)
{
	int device_number;
	int i = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;	// Iterator for device list

						// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure libpcap/WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i< device_number - 1; device = device->next, i++);

	return device;
}

void *wifiThreadFunction(void *params)
{
	int i, j;
	unsigned char* packet_data2;

	for (i = number_of_packets / 2; i < number_of_packets; i++)
	{
		puts("SENDING HALF OF THE FILE OVER WIFI!");
		int len = DEFAULT_BUFLEN;

		if (i == number_of_packets - 1)
		{
			len = sizeOfLast;
		}

		packet_data2 = (char*)malloc(len);

		pthread_mutex_lock(&myMutex);
		idZaWiFi = i + 3;

		packet_data2 = setup_header_wifi(data_array[i], packet_data2, len, idZaWiFi);
		pthread_mutex_unlock(&myMutex);

		if (number_of_packets - 1 == i)
			printf("POSLEDNJI: %d\n\n", len);

		if (pcap_sendpacket(wifi_handle, packet_data2, len + TOTAL_HEADER_SIZE) == -1)
		{
			printf("Packet %d not sent!\n", i);
			break;
		}
		Sleep(2);

		/*Receive ACK for current packet*/
		/*while (pcap_loop(wifi_handle, 0, ack_handler_wifi, NULL) != -2)
		{
			puts("Sending packets again!\n\n");
			pcap_sendpacket(wifi_handle, packet_data2, len);
			Sleep(2);
		}*/

		if (i == number_of_packets - 1)
		{
			if (flagEthernetWorks == 0)
			{
				while (1)
				{
					puts("*******MAJOR FAILURE! ETHERNET DOWN! SENDING VIA WIFI!!!********\n\n");
					for (j = CURRENT_POSITION_OF_ETHERNET_FAILURE; j < number_of_packets / 2; j++)
					{
						puts("SENDING HALF OF THE FILE OVER WIFI!");
						int len = DEFAULT_BUFLEN;

						if (j == (number_of_packets / 2 - 1))
						{
							len = sizeOfLast;
						}

						packet_data2 = (char*)malloc(len);

						pthread_mutex_lock(&myMutex);
						idZaWiFi = j + 3;

						packet_data2 = setup_header_wifi(data_array[i], packet_data2, len, idZaWiFi);
						pthread_mutex_unlock(&myMutex);

						if (number_of_packets - 1 == j)
							printf("POSLEDNJI: %d\n\n", len);

						if (pcap_sendpacket(wifi_handle, packet_data2, len + TOTAL_HEADER_SIZE) == -1)
						{
							printf("Packet %d not sent!\n", i);
							break;
						}
						Sleep(2);


						if (j == (number_of_packets / 2 - 1))
							break;
					}
				}
			}
		}
	}
}