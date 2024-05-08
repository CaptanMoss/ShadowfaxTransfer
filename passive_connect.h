#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <ctype.h>
#include <wsk.h>
#include "libwsk.h"


SOCKET SocketFTP;
#define INITIALISE 0

char* custom_strtok(char* str, const char* delim);
int WSKPassivePort(char* message);
LPCWSTR IntToLPCWSTR(int number);
void FreeMemory(void* ptr);


NTSTATUS WSKConnectPassive(
    _In_opt_ LPCWSTR NodeName,//IP Address
    _In_opt_ LPCWSTR ServiceName,//PORT
    _In_     ADDRESS_FAMILY AddressFamily, //AF_INET
    _In_     USHORT  SocketType // SOCK_STREAM
);



char* custom_strtok(char* str, const char* delim) {
    static char* ptr = NULL;
    if (str) ptr = str;
    else if (!ptr) return NULL;

    char* start = ptr;
    char* end = ptr;

    while (*end != '\0' && !strchr(delim, *end)) {
        end++;
    }

    if (*end == '\0') ptr = NULL;
    else {
        *end = '\0';
        ptr = end + 1;
    }

    return start;
}

int WSKPassivePort(char* message) {
    int i = INITIALISE;
    int count = INITIALISE;
    int port = INITIALISE;
    char* token;
    char delim[] = " ,)";

    while (message[i] != '\0' && count < 4) {
        if (message[i] == ',') {
            count++;
        }
        i++;
    }

    count = 0;

    token = custom_strtok(message + i, delim);
    while (token != NULL) {
        if (isdigit(token[0])) {
            if (count == 1) {
                port += atoi(token);
            }
            if (count == 0) {
                port = atoi(token) * 256;
                count++;
            }
        }
        token = custom_strtok(NULL, delim);
    }
    return port;
}

LPCWSTR IntToLPCWSTR(int number) {
    wchar_t* buffer = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, 20 * sizeof(wchar_t), TAG_POOL);
    if (buffer) {
        RtlStringCbPrintfW(buffer, 20 * sizeof(wchar_t), L"%d", number);
    }
    return buffer;
}

void FreeMemory(void* ptr) {
    if (ptr) {
        ExFreePoolWithTag(ptr, TAG_POOL);
    }
}

NTSTATUS WSKConnectPassive(
    _In_opt_ LPCWSTR NodeName,//IP Address
    _In_opt_ LPCWSTR ServiceName,//PORT
    _In_     ADDRESS_FAMILY AddressFamily, //AF_INET
    _In_     USHORT  SocketType // SOCK_STREAM
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LPWSTR HostName = NULL;
    LPWSTR PortName = NULL;
    PADDRINFOEXW AddrInfo = NULL;

    do
    {
        HostName = (LPWSTR)ExAllocatePoolZero(PagedPool, NI_MAXHOST * sizeof(WCHAR), TAG_POOL);
        PortName = (LPWSTR)ExAllocatePoolZero(PagedPool, NI_MAXSERV * sizeof(WCHAR), TAG_POOL);

        if (HostName == NULL || PortName == NULL)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] ExAllocatePoolZero(Name) failed.\n");

            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ADDRINFOEXW Hints = { 0 };
        Hints.ai_family = AddressFamily;
        Hints.ai_socktype = SocketType;
        Hints.ai_protocol = ((SocketType == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);

        Status = WSKGetAddrInfo(NodeName, ServiceName, NS_ALL, NULL,
            &Hints, &AddrInfo, WSK_INFINITE_WAIT, NULL, NULL);
        if (!NT_SUCCESS(Status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] WSKGetAddrInfo failed: 0x%08X.\n",
                Status);

            break;
        }

        // Make sure we got at least one address back
        if (AddrInfo == NULL)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] Server (%ls) name could not be resolved!\n",
                NodeName);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        for (PADDRINFOEXW Addr = AddrInfo; Addr; Addr = Addr->ai_next)
        {
            Status = WSKSocket(&SocketFTP, (ADDRESS_FAMILY)(Addr->ai_family),
                (USHORT)(Addr->ai_socktype), Addr->ai_protocol, NULL);
            if (!NT_SUCCESS(Status))
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WSK] [Client] WSKSocket failed: 0x%08X.\n",
                    Status);

                break;
            }

            Status = WSKGetNameInfo(Addr->ai_addr, (ULONG)(Addr->ai_addrlen),
                HostName, NI_MAXHOST, PortName, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
            if (!NT_SUCCESS(Status))
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WSK] [Client] WSKGetNameInfo failed: 0x%08X.\n",
                    Status);

                break;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] Client attempting connection to: %ls port: %ls.\n",
                HostName, PortName);

            if (Addr->ai_socktype == SOCK_STREAM)
            {
                Status = WSKConnect(SocketFTP, Addr->ai_addr, Addr->ai_addrlen);
            }

            if (Addr->ai_socktype == SOCK_DGRAM)
            {
                Status = WSKIoctl(SocketFTP, SIO_WSK_SET_SENDTO_ADDRESS,
                    Addr->ai_addr, Addr->ai_addrlen, NULL, 0, NULL, NULL, NULL);
            }

            if (NT_SUCCESS(Status))
            {
                break;
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] Unable to establish connection... 0x%08X.\n",
                Status);

            break;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] Connection established...\n");


    } while (FALSE);

    if (HostName)
    {
        ExFreePoolWithTag(HostName, TAG_POOL);
    }

    if (PortName)
    {
        ExFreePoolWithTag(PortName, TAG_POOL);
    }

    if (AddrInfo)
    {
        WSKFreeAddrInfo(AddrInfo);
    }

    if (!NT_SUCCESS(Status))
    {
        //CloseWSKClient(SocketFTP, ClientFTPFileUpload);
    }

    return Status;
}

