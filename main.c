/*
 * HansCli - Lightweight IP over ICMP client for Linux
 * Copyright (C) 2015 Vittorio Gambaletta <openwrt@vittgam.net>
 *
 * Based on Hans - IP over ICMP
 * Copyright (C) 2009 Friedrich Schöller <hans@schoeller.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

enum {
	STATE_CLOSED,
	STATE_CONNECTION_REQUEST_SENT,
	STATE_CHALLENGE_RESPONSE_SENT,
	STATE_ESTABLISHED
};

enum {
	TYPE_RESET_CONNECTION	= 1,
	TYPE_CONNECTION_REQUEST	= 2,
	TYPE_CHALLENGE			= 3,
	TYPE_CHALLENGE_RESPONSE	= 4,
	TYPE_CONNECTION_ACCEPT	= 5,
	TYPE_CHALLENGE_ERROR	= 6,
	TYPE_DATA				= 7,
	TYPE_POLL				= 8,
	TYPE_SERVER_FULL		= 9
};

#define MAX_BUFFERED_PACKETS 20

#define KEEP_ALIVE_INTERVAL (60 * 1000)
#define POLL_INTERVAL 2000

#define CHALLENGE_SIZE 20

//#define DEBUG_ONLY(a) a
#define DEBUG_ONLY(a)

#define ECHO_HEADER_LEN 8
#define HANS_HEADER_LEN 5

#define TUNNEL_HEADER_TYPE_RECV *(uint8_t *)(receiveBuffer + sizeof(struct ip) + ECHO_HEADER_LEN + 4)

#include "libsha1.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <sys/types.h>
#include <pwd.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

uint32_t serverIp = INADDR_NONE;
const char *userName = NULL;
const char *password = "";
char deviceName[IFNAMSIZ] = {0};
int foreground = 0;
int tunnelMtu = 1500;
int maxPolls = 10;
uid_t uid = 0;
gid_t gid = 0;
int changeEchoId = 0;
int changeEchoSeq = 0;
int verbose = 0;
int alive = 1;
int echofd, tunfd, privilegesDropped = 0;
uint16_t nextEchoId, nextEchoSequence;
void *sendBuffer, *receiveBuffer;
uint32_t clientIp = INADDR_NONE;
int state = STATE_CLOSED;
struct timeval nextTimeout;
char icmp_filter;
struct ifreq ifr;
int ret = 0;

static void sig_term_handler(int unused)
{
	syslog(LOG_INFO, "SIGTERM received");
	alive = 0;
}

static void sig_int_handler(int unused)
{
	syslog(LOG_INFO, "SIGINT received");
	alive = 0;
}

static void usage()
{
	printf(
		"HansCli - Lightweight IP over ICMP client for Linux, based on Hans version 0.4.4\n\n"
		"RUN AS CLIENT\n"
		"  hanscli -c server [-fv] [-p password] [-u unprivileged_user] [-d tun_device] [-m reference_mtu] [-w polls]\n\n"
		"ARGUMENTS\n"
		"  -c server     Connect to a server.\n"
		"  -f            Run in foreground.\n"
		"  -v            Print debug information.\n"
		"  -p password   Use a password.\n"
		"  -u username   Set the user under which the program should run.\n"
		"  -d device     Use the given tun device.\n"
		"  -m mtu        Use this mtu to calculate the tunnel mtu.\n"
		"                The generated echo packets will not be bigger than this value.\n"
		"                Has to be the same on client and server. Defaults to 1500.\n"
		"  -w polls      Number of echo requests the client sends to the server for polling.\n"
		"                0 disables polling. Defaults to 10.\n"
		"  -i            Change the echo id for every echo request.\n"
		"  -q            Change the echo sequence number for every echo request.\n"
	);
}

static void setTimeout(int ms)
{
	nextTimeout.tv_sec = ms / 1000;
	nextTimeout.tv_usec = (ms % 1000) * 1000;
}

static void sendEchoToServer(int type, int dataLength)
{
	if (maxPolls == 0 && state == STATE_ESTABLISHED)
		setTimeout(KEEP_ALIVE_INTERVAL);
	if (dataLength > tunnelMtu) {
		syslog(LOG_ERR, "packet too big");
	} else {
		memcpy(sendBuffer + ECHO_HEADER_LEN, "hanc", 4);
		*(uint8_t *)(sendBuffer + ECHO_HEADER_LEN + 4) = type;

		DEBUG_ONLY(printf("sending: type %d, length %d, id %d, seq %d\n", type, dataLength, nextEchoId, nextEchoSequence));

		*(uint8_t *)(sendBuffer) = 8; // type
		*(uint8_t *)(sendBuffer + 1) = 0; // code
		*(uint16_t *)(sendBuffer + 2) = 0; // checksum
		*(uint16_t *)(sendBuffer + 4) = htons(nextEchoId);
		*(uint16_t *)(sendBuffer + 6) = htons(nextEchoSequence);

		uint16_t *data16 = (uint16_t *)sendBuffer;
		int length = dataLength + ECHO_HEADER_LEN + HANS_HEADER_LEN;
		uint32_t sum = 0;
		for (sum = 0; length > 1; length -= 2)
			sum += *data16++;
		if (length == 1) {
			uint16_t last = *(unsigned char *)data16;
			last <<= 8;
			sum += ntohs (last);
		}
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
		*(uint16_t *)(sendBuffer + 2) = ~sum;

		struct sockaddr_in target;
		target.sin_family = AF_INET;
		target.sin_addr.s_addr = htonl(serverIp);
		int result = sendto(echofd, sendBuffer, dataLength + ECHO_HEADER_LEN + HANS_HEADER_LEN, 0, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
		if (result == -1)
			syslog(LOG_ERR, "error sending icmp packet: %s", strerror(errno));

		if (changeEchoId)
			nextEchoId = nextEchoId + 38543; // some random prime
		if (changeEchoSeq)
			nextEchoSequence = nextEchoSequence + 38543; // some random prime
	}
}

static void sendConnectionRequest()
{
	syslog(LOG_DEBUG, "sending connection request");

	memset(sendBuffer, 0, 8);
	*(uint8_t *)(sendBuffer + ECHO_HEADER_LEN + HANS_HEADER_LEN) = maxPolls;
	*(uint32_t *)(sendBuffer + ECHO_HEADER_LEN + HANS_HEADER_LEN + 4) = htonl(clientIp);

	sendEchoToServer(TYPE_CONNECTION_REQUEST, 8);

	state = STATE_CONNECTION_REQUEST_SENT;
	setTimeout(5000);
}

int main(int argc, char *argv[])
{
	openlog(argv[0], LOG_PERROR, LOG_DAEMON);

	int c;
	while ((c = getopt(argc, argv, "fu:d:p:c:m:w:qiv")) != -1) {
		switch(c) {
			case 'f':
				foreground = 1;
				break;
			case 'u':
				userName = optarg;
				break;
			case 'd':
				strncpy(deviceName, optarg, IFNAMSIZ);
				deviceName[IFNAMSIZ - 1] = 0;
				break;
			case 'p':
				password = strdup(optarg);
				memset(optarg, 0, strlen(optarg));
				break;
			case 'c':
				serverIp = inet_addr(optarg);
				if (serverIp != INADDR_NONE) {
					serverIp = ntohl(serverIp);
				} else {
					struct hostent* he = gethostbyname(optarg);
					if (!he) {
						syslog(LOG_ERR, "gethostbyname: %s", hstrerror(h_errno));
					} else {
						serverIp = ntohl(*(uint32_t *)he->h_addr);
					}
				}
				break;
			case 'm':
				tunnelMtu = atoi(optarg);
				break;
			case 'w':
				maxPolls = atoi(optarg);
				break;
			case 'q':
				changeEchoSeq = 1;
				break;
			case 'i':
				changeEchoId = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'a':
				break;
			default:
				usage();
				return 1;
		}
	}

	tunnelMtu -= sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN;

	if (tunnelMtu < 68) {
		// RFC 791: Every internet module must be able to forward a datagram of 68 octets without further fragmentation.
		printf("mtu too small\n");
		return 1;
	}

	if (serverIp == INADDR_NONE || maxPolls < 0 || maxPolls > 255) {
		usage();
		return 1;
	}

	if (userName != NULL) {
		struct passwd *pw = getpwnam(userName);
		if (pw != NULL) {
			uid = pw->pw_uid;
			gid = pw->pw_gid;
		} else {
			syslog(LOG_ERR, "user not found");
			return 1;
		}
	}

	if (!verbose)
		setlogmask(LOG_UPTO(LOG_INFO));

	signal(SIGTERM, sig_term_handler);
	signal(SIGINT, sig_int_handler);

	sendBuffer = malloc(sizeof(char) * (tunnelMtu + ECHO_HEADER_LEN + HANS_HEADER_LEN));
	if (!sendBuffer) {
		syslog(LOG_ERR, "cannot allocate memory for send buffer");
		return 1;
	}

	receiveBuffer = malloc(sizeof(char) * (tunnelMtu + sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN));
	if (!receiveBuffer) {
		syslog(LOG_ERR, "cannot allocate memory for receive buffer");
		return 1;
	}

	srand(time(NULL));
	nextEchoId = rand();
	nextEchoSequence = rand();

	echofd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (echofd == -1) {
		syslog(LOG_ERR, "creating icmp socket: %s", strerror(errno));
		return 1;
	}

	icmp_filter = ~(1<<ICMP_ECHOREPLY);
	if (setsockopt(echofd, SOL_RAW, ICMP_FILTER, &icmp_filter, sizeof(icmp_filter)) < 0) {
		syslog(LOG_ERR, "setsockopt(ICMP_FILTER): %s", strerror(errno));
		return 1;
	}

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		syslog(LOG_ERR, "could not create tunnel device: %s", strerror(errno));
		return 1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
	if (ioctl(tunfd, TUNSETIFF, &ifr) < 0) {
		syslog(LOG_ERR, "could not create tunnel device: %s", strerror(errno));
		close(tunfd);
		return 1;
	} 
	strncpy(deviceName, ifr.ifr_name, IFNAMSIZ);
	deviceName[IFNAMSIZ - 1] = 0;

	syslog(LOG_INFO, "opened tunnel device: %s", deviceName);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = tunnelMtu;
	if (ioctl(echofd, SIOCSIFMTU, &ifr) < 0)
		syslog(LOG_ERR, "could not set tun device mtu: %s", strerror(errno));

	if (!foreground) {
		syslog(LOG_INFO, "detaching from terminal");
		daemon(0, 0);
	}

	// start
	sendConnectionRequest();

	int maxFd = (echofd > tunfd ? echofd : tunfd) + 1;

	while (alive) {
		fd_set fs;

		FD_ZERO(&fs);
		FD_SET(tunfd, &fs);
		FD_SET(echofd, &fs);

		// wait for data or timeout
		int result = select(maxFd, &fs, NULL, NULL, &nextTimeout);
		if (result == -1) {
			if (alive) {
				syslog(LOG_ERR, "select: %s", strerror(errno));
				ret = 1;
			}
			break;
		}

		// timeout
		if (result == 0) {
			if ((state == STATE_CONNECTION_REQUEST_SENT) || (state == STATE_CHALLENGE_RESPONSE_SENT)) {
				sendConnectionRequest();
			} else if (state == STATE_ESTABLISHED) {
				sendEchoToServer(TYPE_POLL, 0);
				setTimeout(maxPolls == 0 ? KEEP_ALIVE_INTERVAL : POLL_INTERVAL);
			} else {
				syslog(LOG_ERR, "server is dead");
				ret = 1;
				break;
			}
			continue;
		}

		// icmp data
		if (FD_ISSET(echofd, &fs)) {
			struct sockaddr_in source;
			int source_addr_len = sizeof(struct sockaddr_in);
			int dataLength = recvfrom(echofd, receiveBuffer, tunnelMtu + sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN, 0, (struct sockaddr *)&source, (socklen_t *)&source_addr_len);
			if (dataLength == -1) {
				syslog(LOG_ERR, "error receiving icmp packet: %s", strerror(errno));
			} else if (dataLength >= sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN && ntohl(source.sin_addr.s_addr) == serverIp) {
				if (*(uint8_t *)(receiveBuffer + sizeof(struct ip)) == 0 && *(uint8_t *)(receiveBuffer + sizeof(struct ip) + 1) == 0) {
					dataLength -= sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN;
					DEBUG_ONLY(printf("received: type %d, length %d, id %d, seq %d\n", TUNNEL_HEADER_TYPE_RECV, dataLength, ntohs(*(uint16_t *)(receiveBuffer + sizeof(struct ip) + 2)), ntohs(*(uint16_t *)(receiveBuffer + sizeof(struct ip) + 4))));
					if (!memcmp(receiveBuffer + sizeof(struct ip) + ECHO_HEADER_LEN, "hans", 4)) {
						if (TUNNEL_HEADER_TYPE_RECV == TYPE_RESET_CONNECTION) {
							syslog(LOG_DEBUG, "reset received");
							sendConnectionRequest();
						} else if (TUNNEL_HEADER_TYPE_RECV == TYPE_SERVER_FULL && state == STATE_CONNECTION_REQUEST_SENT) {
							syslog(LOG_ERR, "server full");
							ret = 1;
							break;
						} else if (TUNNEL_HEADER_TYPE_RECV == TYPE_CHALLENGE && state == STATE_CONNECTION_REQUEST_SENT) {
							syslog(LOG_DEBUG, "challenge received");
							if (dataLength != CHALLENGE_SIZE) {
								syslog(LOG_ERR, "invalid challenge received");
								ret = 1;
								break;
							} else {
								state = STATE_CHALLENGE_RESPONSE_SENT;
								syslog(LOG_DEBUG, "sending challenge response");
								sha1_ctx cx;
								int i;
								sha1_begin(&cx);
								sha1_hash(password, strlen(password), &cx);
								sha1_hash(receiveBuffer + sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN, dataLength, &cx);
								sha1_end((unsigned char *)(sendBuffer + ECHO_HEADER_LEN + HANS_HEADER_LEN), &cx);
								sendEchoToServer(TYPE_CHALLENGE_RESPONSE, 20);
								setTimeout(5000);
							}
						} else if (TUNNEL_HEADER_TYPE_RECV == TYPE_CONNECTION_ACCEPT && state == STATE_CHALLENGE_RESPONSE_SENT) {
							if (dataLength != sizeof(uint32_t)) {
								syslog(LOG_ERR, "invalid ip received");
								ret = 1;
								break;
							} else {
								syslog(LOG_INFO, "connection established");
								uint32_t newClientIp = ntohl(*(uint32_t *)(receiveBuffer + sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN));
								if (newClientIp != clientIp) {
									if (privilegesDropped) {
										syslog(LOG_ERR, "could not get the same ip address, so root privileges are required to change it");
										ret = 1;
										break;
									}
									clientIp = newClientIp;

									memset(&ifr, 0, sizeof(ifr));
									strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
									(*(struct sockaddr_in *)(&ifr.ifr_addr)).sin_family = AF_INET;
									(*(struct sockaddr_in *)(&ifr.ifr_addr)).sin_addr.s_addr = htonl(newClientIp);
									if (ioctl(echofd, SIOCSIFADDR, &ifr) < 0)
										syslog(LOG_ERR, "could not set tun device ip address: %s", strerror(errno));

									memset(&ifr, 0, sizeof(ifr));
									strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
									(*(struct sockaddr_in *)(&ifr.ifr_dstaddr)).sin_family = AF_INET;
									(*(struct sockaddr_in *)(&ifr.ifr_dstaddr)).sin_addr.s_addr = htonl((newClientIp & 0xffffff00) + 1);
									if (ioctl(echofd, SIOCSIFDSTADDR, &ifr) < 0)
										syslog(LOG_ERR, "could not set tun device destination ip address: %s", strerror(errno));

									memset(&ifr, 0, sizeof(ifr));
									strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
									(*(struct sockaddr_in *)(&ifr.ifr_netmask)).sin_family = AF_INET;
									(*(struct sockaddr_in *)(&ifr.ifr_netmask)).sin_addr.s_addr = htonl(0xffffffff);
									if (ioctl(echofd, SIOCSIFNETMASK, &ifr) < 0)
										syslog(LOG_ERR, "could not set tun device ip netmask: %s", strerror(errno));

									memset(&ifr, 0, sizeof(ifr));
									strncpy(ifr.ifr_name, deviceName, sizeof(ifr.ifr_name));
									if (ioctl(echofd, SIOCGIFFLAGS, &ifr) < 0) {
										syslog(LOG_ERR, "could not get tun device flags: %s", strerror(errno));
									} else {
										ifr.ifr_flags |= IFF_UP;// | IFF_RUNNING;
										if (ioctl(echofd, SIOCSIFFLAGS, &ifr) < 0)
											syslog(LOG_ERR, "could not set tun device up: %s", strerror(errno));
									}
								}
								state = STATE_ESTABLISHED;
								if (uid > 0 && !privilegesDropped) {
									syslog(LOG_INFO, "dropping privileges");
									if (setgid(gid) == -1) {
										syslog(LOG_ERR, "setgid: %s", strerror(errno));
										ret = 1;
										break;
									}
									if (setuid(uid) == -1) {
										syslog(LOG_ERR, "setuid: %s", strerror(errno));
										ret = 1;
										break;
									}
									privilegesDropped = 1;
								}
								if (maxPolls == 0) {
									setTimeout(KEEP_ALIVE_INTERVAL);
								} else {
									int i;
									for (i = 0; i < maxPolls; i++)
										sendEchoToServer(TYPE_POLL, 0);
									setTimeout(POLL_INTERVAL);
								}
							}
						} else if (TUNNEL_HEADER_TYPE_RECV == TYPE_CHALLENGE_ERROR && state == STATE_CHALLENGE_RESPONSE_SENT) {
							syslog(LOG_ERR, "password error");
							ret = 1;
							break;
						} else if (TUNNEL_HEADER_TYPE_RECV == TYPE_DATA && state == STATE_ESTABLISHED) {
							if (dataLength == 0) {
								syslog(LOG_WARNING, "received empty data packet");
							} else {
								if (write(tunfd, receiveBuffer + sizeof(struct ip) + ECHO_HEADER_LEN + HANS_HEADER_LEN, dataLength) == -1)
									syslog(LOG_ERR, "error writing %d bytes to tun: %s", dataLength, strerror(errno));
								if (maxPolls != 0)
									sendEchoToServer(TYPE_POLL, 0);
							}
						} else {
							syslog(LOG_DEBUG, "invalid packet type: %d, state: %d", TUNNEL_HEADER_TYPE_RECV, state);
						}
					}
				}
			}
		}

		// data from tun
		if (FD_ISSET(tunfd, &fs)) {
			int dataLength = read(tunfd, sendBuffer + ECHO_HEADER_LEN + HANS_HEADER_LEN, tunnelMtu);
			if (dataLength == -1) {
				syslog(LOG_ERR, "error reading from tun: %s", strerror(errno));
			} else if (dataLength == 0) {
				syslog(LOG_ERR, "tunnel closed");
				ret = 1;
				break;
			} else if (state == STATE_ESTABLISHED) {
				sendEchoToServer(TYPE_DATA, dataLength);
			}
		}
	}
	// end

	close(tunfd);
	close(echofd);
	free(sendBuffer);
	free(receiveBuffer);

	return ret;
}
