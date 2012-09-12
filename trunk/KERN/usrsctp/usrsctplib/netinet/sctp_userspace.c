/*-
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#if defined (__Userspace_os_Windows)
#include <netinet/sctp_pcb.h>
#include <sys/timeb.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#endif
#include <netinet/sctp_os_userspace.h>

#if !defined (__Userspace_os_Windows)
int
sctp_userspace_get_mtu_from_ifn(uint32_t if_index, int af)
{
	struct ifreq ifr;
	int fd;

	if_indextoname(if_index, ifr.ifr_name);
	/* TODO can I use the raw socket here and not have to open a new one with each query? */
	if ((fd = socket(af, SOCK_DGRAM, 0)) < 0)
		return (0);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		close(fd);
		return (0);
	}
	close(fd);
	return ifr.ifr_mtu;
}
#endif

#if defined (__Userspace_os_Windows)
int
sctp_userspace_get_mtu_from_ifn(uint32_t if_index, int af)
{
	PIP_ADAPTER_ADDRESSES pAdapterAddrs, pAdapt;
	DWORD AdapterAddrsSize, Err;

	AdapterAddrsSize = 0;
	if ((Err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &AdapterAddrsSize)) != 0) {
		if ((Err != ERROR_BUFFER_OVERFLOW) && (Err != ERROR_INSUFFICIENT_BUFFER)) {
			SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersAddresses() sizing failed with error code %d, AdapterAddrsSize = %d\n", Err, AdapterAddrsSize);
			return (-1);
		}
	}
	if ((pAdapterAddrs = (PIP_ADAPTER_ADDRESSES) GlobalAlloc(GPTR, AdapterAddrsSize)) == NULL) {
		SCTPDBG(SCTP_DEBUG_USR, "Memory allocation error!\n");
		return (-1);
	}
	if ((Err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAdapterAddrs, &AdapterAddrsSize)) != ERROR_SUCCESS) {
		SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersAddresses() failed with error code %d\n", Err);
		return (-1);
	}
	for (pAdapt = pAdapterAddrs; pAdapt; pAdapt = pAdapt->Next) {
		if (pAdapt->IfIndex == if_index)
			return (pAdapt->Mtu);
	}
	return (0);
}

void
getwintimeofday(struct timeval *tv)
{
	struct timeb tb;

	ftime(&tb);
	tv->tv_sec = tb.time;
 	tv->tv_usec = tb.millitm * 1000;
}

int
Win_getifaddrs(struct ifaddrs** interfaces)
{
	DWORD Err, AdapterAddrsSize;
	int count;
	PIP_ADAPTER_ADDRESSES pAdapterAddrs, pAdapt;
	struct ifaddrs *ifa;
#if defined(INET)
	struct sockaddr_in *addr;
#endif
#if defined(INET6)
	struct sockaddr_in6 *addr6;
#endif
	count = 0;
#if defined(INET)
	AdapterAddrsSize = 0;
	if ((Err = GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &AdapterAddrsSize)) != 0) {
		if ((Err != ERROR_BUFFER_OVERFLOW) && (Err != ERROR_INSUFFICIENT_BUFFER)) {
			SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersV4Addresses() sizing failed with error code %d and AdapterAddrsSize = %d\n", Err, AdapterAddrsSize);
			return (-1);
		}
	}
	/* Allocate memory from sizing information */
	if ((pAdapterAddrs = (PIP_ADAPTER_ADDRESSES) GlobalAlloc(GPTR, AdapterAddrsSize)) == NULL) {
		SCTPDBG(SCTP_DEBUG_USR, "Memory allocation error!\n");
		return (-1);
	}
	/* Get actual adapter information */
	if ((Err = GetAdaptersAddresses(AF_INET, 0, NULL, pAdapterAddrs, &AdapterAddrsSize)) != ERROR_SUCCESS) {
		SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersV4Addresses() failed with error code %d\n", Err);
		return (-1);
	}
	/* Enumerate through each returned adapter and save its information */
	for (pAdapt = pAdapterAddrs, count; pAdapt; pAdapt = pAdapt->Next, count++) {
		addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		ifa = (struct ifaddrs *)malloc(sizeof(struct ifaddrs));
		if ((addr == NULL) || (ifa == NULL)) {
			SCTPDBG(SCTP_DEBUG_USR, "Can't allocate memory\n");
			return (-1);
		}
		ifa->ifa_name = strdup(pAdapt->AdapterName);
		ifa->ifa_flags = pAdapt->Flags;
		ifa->ifa_addr = (struct sockaddr *)addr;
		memcpy(&addr, &pAdapt->FirstUnicastAddress->Address.lpSockaddr, sizeof(struct sockaddr_in));
		interfaces[count] = ifa;
	}
#endif
#if defined(INET6)
	if (SCTP_BASE_VAR(userspace_rawsctp6) != -1) {
		AdapterAddrsSize = 0;
		if ((Err = GetAdaptersAddresses(AF_INET6, 0, NULL, NULL, &AdapterAddrsSize)) != 0) {
			if ((Err != ERROR_BUFFER_OVERFLOW) && (Err != ERROR_INSUFFICIENT_BUFFER)) {
				SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersV6Addresses() sizing failed with error code %d AdapterAddrsSize = %d\n", Err, AdapterAddrsSize);
				return (-1);
			}
		}
		/* Allocate memory from sizing information */
		if ((pAdapterAddrs = (PIP_ADAPTER_ADDRESSES) GlobalAlloc(GPTR, AdapterAddrsSize)) == NULL) {
			SCTPDBG(SCTP_DEBUG_USR, "Memory allocation error!\n");
			return (-1);
		}
		/* Get actual adapter information */
		if ((Err = GetAdaptersAddresses(AF_INET6, 0, NULL, pAdapterAddrs, &AdapterAddrsSize)) != ERROR_SUCCESS) {
			SCTPDBG(SCTP_DEBUG_USR, "GetAdaptersV6Addresses() failed with error code %d\n", Err);
			return (-1);
		}
		/* Enumerate through each returned adapter and save its information */
		for (pAdapt = pAdapterAddrs, count; pAdapt; pAdapt = pAdapt->Next, count++) {
			addr6 = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
			ifa = (struct ifaddrs *)malloc(sizeof(struct ifaddrs));
			if ((addr6 == NULL) || (ifa == NULL)) {
				SCTPDBG(SCTP_DEBUG_USR, "Can't allocate memory\n");
				return (-1);
			}
			ifa->ifa_name = strdup(pAdapt->AdapterName);
			ifa->ifa_flags = pAdapt->Flags;
			ifa->ifa_addr = (struct sockaddr *)addr6;
			memcpy(&addr6, &pAdapt->FirstUnicastAddress->Address.lpSockaddr, sizeof(struct sockaddr_in6));
			interfaces[count] = ifa;
		}
	}
#endif
	return (0);
}

int
win_if_nametoindex(const char *ifname)
{
	IP_ADAPTER_ADDRESSES *addresses, *addr;
	ULONG status, size;
	int index = 0;

	if (!ifname) {
		return 0;
	}

	size = 0;
	status = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
	if (status != ERROR_BUFFER_OVERFLOW) {
		return 0;
	}
	addresses = malloc(size);
	status = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &size);
	if (status == ERROR_SUCCESS) {
		for (addr = addresses; addr; addr = addr->Next) {
			if (addr->AdapterName && !strcmp(ifname, addr->AdapterName)) {
				index = addr->IfIndex;
				break;
			}
		}
	}

	free(addresses);
	return index;
}

#if defined (_WIN32_WINNT)
/* These functions are written based on the code at 
 * http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
 */

void
InitializeXPConditionVariable(userland_cond_t *cv)
{
	cv->waiters_count = 0;
	InitializeCriticalSection(&(cv->waiters_count_lock));
	cv->events_[C_SIGNAL] = CreateEvent (NULL, FALSE, FALSE, NULL);
	cv->events_[C_BROADCAST] = CreateEvent (NULL, TRUE, FALSE, NULL);
}

int
SleepXPConditionVariable(userland_cond_t *cv, userland_mutex_t *mtx)
{
	int result, last_waiter;

	EnterCriticalSection(&cv->waiters_count_lock);
	cv->waiters_count++;
	LeaveCriticalSection(&cv->waiters_count_lock);
	LeaveCriticalSection (mtx);
	result = WaitForMultipleObjects(2, cv->events_, FALSE, INFINITE);
	if (result==-1) {
		result = GetLastError();
	}
	EnterCriticalSection(&cv->waiters_count_lock);
	cv->waiters_count--;
	last_waiter = 
		result == (C_SIGNAL + C_BROADCAST && (cv->waiters_count == 0));
	LeaveCriticalSection(&cv->waiters_count_lock);
	if (last_waiter)
		ResetEvent(cv->events_[C_BROADCAST]);
	EnterCriticalSection (mtx);
	return result;
}

void
WakeAllXPConditionVariable(userland_cond_t *cv)
{
	int have_waiters;
	EnterCriticalSection(&cv->waiters_count_lock);
	have_waiters = cv->waiters_count > 0;
	LeaveCriticalSection(&cv->waiters_count_lock);
	if (have_waiters)
		SetEvent (cv->events_[C_BROADCAST]);
}
#endif
#endif
