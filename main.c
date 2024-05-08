#include "libwsk.h"
#include "passive_connect.h"


#define IP_ADDRESS                  L"192.168.11.68"
#define TCP_PORT                    L"21"
#define MAXSZ 100  


#define DebuggerPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__);
#define DATA_BUFSIZE 4096


EXTERN_C_START
DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;
EXTERN_C_END


const size_t DEFAULT_BUFFER_LEN = PAGE_SIZE;
SOCKET    ClientSocket = WSK_INVALID_SOCKET;
PETHREAD  ClientThread = NULL;

PETHREAD  ClientFTPFileUpload = NULL;
LPCWSTR PORTSTR = NULL;

VOID WSKClientThread(
    _In_ PVOID Context
);

NTSTATUS StartWSKClient(
    _In_opt_ LPCWSTR NodeName,
    _In_opt_ LPCWSTR ServiceName,
    _In_     ADDRESS_FAMILY AddressFamily,
    _In_     USHORT  SocketType
);

VOID CloseWSKClient(
    SOCKET    LocalSocket,
    PETHREAD LocalThread
);

VOID FTPUploadFile(
    SOCKET   Socket
);

VOID WSKClientFTPFileUpload(
    _In_ PVOID Context
);

VOID WSKFTPSendFile(SOCKET SocketLocal);

VOID DriverUnload(_In_ DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    CloseWSKClient(ClientSocket, ClientThread);
    WSKCleanup();
}

NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;

    do
    {
        ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
        DriverObject->DriverUnload = DriverUnload;

        WSKDATA WSKData = { 0 };
        Status = WSKStartup(MAKE_WSK_VERSION(1, 0), &WSKData);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        Status = StartWSKClient(IP_ADDRESS,
            TCP_PORT,
            AF_INET,
            SOCK_STREAM);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

    } while (FALSE);

    if (!NT_SUCCESS(Status))
    {
        DriverUnload(DriverObject);
    }

    return Status;
}

NTSTATUS StartWSKClient(
    _In_opt_ LPCWSTR NodeName,
    _In_opt_ LPCWSTR ServiceName,
    _In_     ADDRESS_FAMILY AddressFamily,
    _In_     USHORT  SocketType
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ADDRINFOEXW Hints = { 0 };
    PADDRINFOEXW AddrInfo = NULL;
    LPWSTR HostName = NULL;
    LPWSTR PortName = NULL;

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
            Status = WSKSocket(&ClientSocket, (ADDRESS_FAMILY)(Addr->ai_family),
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
                Status = WSKConnect(ClientSocket, Addr->ai_addr, Addr->ai_addrlen);
            }

            if (Addr->ai_socktype == SOCK_DGRAM)
            {
                Status = WSKIoctl(ClientSocket, SIO_WSK_SET_SENDTO_ADDRESS,
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

        HANDLE ThreadHandle = NULL;
        Status = PsCreateSystemThread(&ThreadHandle, SYNCHRONIZE, NULL, NULL, NULL, &WSKClientThread, (PVOID)ClientSocket);
        if (!NT_SUCCESS(Status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WSK] [Client] PsCreateSystemThread failed: 0x%08X.\n",
                Status);

            break;
        }

        Status = ObReferenceObjectByHandleWithTag(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, TAG_POOL, (PVOID*)&ClientThread, NULL);
        if (NULL != ThreadHandle)
        {
            ZwClose(ThreadHandle);
            ThreadHandle = NULL;
        }

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
        CloseWSKClient(ClientSocket, ClientThread);
    }

    return Status;
}
VOID WSKClientThread(
    _In_ PVOID Context
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    SOCKET   Socket = (SOCKET)Context;

    char    Buffer[PAGE_SIZE] = { 0 };
    char USER[PAGE_SIZE] = "USER ftpuser\r\n"; 
    char PASSWORD[PAGE_SIZE] = "PASS 123456\r\n";

    SIZE_T Bytes = 0u;
    INT    SocketType = 0;

    Bytes = sizeof SocketType;
    Status = WSKGetSocketOpt(Socket, SOL_SOCKET, SO_TYPE, &SocketType, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] WSKGetSocketOpt(SO_TYPE) failed: 0x%08X.\n",
            Status);

        return Status;
    }

    ULONG RecvTimeout = 1000u; // ms
    Bytes = sizeof RecvTimeout;
    Status = WSKSetSocketOpt(Socket, SOL_SOCKET, SO_RCVTIMEO, &RecvTimeout, Bytes);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] WSKSetSocketOpt(SO_RCVTIMEO) failed: 0x%08X.\n",
            Status);

        return Status;
    }

    SIZE_T BufferLength = DEFAULT_BUFFER_LEN;
    SIZE_T LoopCount = 0u;


    if (SocketType == SOCK_STREAM)
    {
        /* Receive message from server "Server will send 220" */
        while ((Status = WSKReceive(Socket, Buffer, sizeof(Buffer) - 1, &Bytes, 0, NULL, NULL)) == 0)
        {
            Buffer[Bytes] = '\0';
            if (!NT_SUCCESS(Status))
            {
                DebuggerPrint("[WSK] [Client] WSKReceive1 failed: 0x%08X.\n", Status);

                break;
            }

            if (Bytes == 0)
            {
                continue;
            }

            if (strstr(Buffer, "220") > 0 || strstr(Buffer, "421") > 0)
                break; //break this while
        }

        DebuggerPrint("[WSK] [Client] Read  %Id bytes, data [%s] from server.\n", Bytes, (LPCSTR)Buffer);

        Status = WSKSend(Socket, USER, strlen(USER), &Bytes, 0, NULL, NULL); /* Send username to server */

        if (!NT_SUCCESS(Status))
        {
            DebuggerPrint("[WSK] [Client] WSKSend failed: 0x%08X.\n", Status);
            return Status;
        }

        /*
            Receive message from server after sending user name.
            Message with code 331 asks you to enter password corresponding to user.
            Message with code 230 means no password is required for the entered username(LOGIN successful).
        */

        while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
        {
            Buffer[Bytes] = '\0';

            if (!NT_SUCCESS(Status))
            {
                DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

                break;
            }

            if (Bytes == 0)
            {
                continue;
            }
            if (strncmp(Buffer, "331", 3) == 0)
            {
                break;
            }

        }

        Status = WSKSend(Socket, PASSWORD, strlen(PASSWORD), &Bytes, 0, NULL, NULL);/* Send password to server */

        if (!NT_SUCCESS(Status))
        {
            DebuggerPrint("[WSK] [Client] WSKSend failed: 0x%08X.\n", Status);
            return Status;
        }

        while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
        {
            Buffer[Bytes] = '\0';
            if (!NT_SUCCESS(Status))
            {
                DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

                break;
            }

            if (Bytes == 0)
            {
                continue;
            }

            if (strncmp(Buffer, "230", 3) == 0)
            {
                break;
            }
        }

        FTPUploadFile(Socket); //Upload file
    }

    PsTerminateSystemThread(Status);
}

VOID FTPUploadFile(SOCKET   Socket)
{
    NTSTATUS Status;
    SIZE_T Bytes = 0u;
    char Buffer[PAGE_SIZE] = { '\0' };

    strcpy(Buffer, "TYPE I\r\n");
    Status = WSKSend(Socket, Buffer, strlen(Buffer), &Bytes, 0, NULL, NULL);/* Tell server to change to BINARY mode */

    memset(Buffer, '\0', sizeof(Buffer));

    while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
    {
        Buffer[Bytes] = '\0';
        if (!NT_SUCCESS(Status))
        {
            DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

            break;
        }

        if (Bytes == 0)
        {
            continue;
        }

        if (strncmp(Buffer, "200", 3) == 0)
            break;
    }

    memset(Buffer, '\0', sizeof(Buffer));

    strcpy(Buffer, "PASV\r\n");
    Status = WSKSend(Socket, Buffer, strlen(Buffer), &Bytes, 0, NULL, NULL); /* Send request for PASSIVE connection */


    while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
    {
        Buffer[Bytes] = '\0';
        if (!NT_SUCCESS(Status))
        {
            DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

            break;
        }

        if (Bytes == 0)
        {
            continue;
        }

        if (strncmp(Buffer, "227", 3) == 0)
            break;
    }


    int PORT = WSKPassivePort(Buffer); /* Generate a PORT number using PORT variables */
    PORTSTR = IntToLPCWSTR(PORT);

    HANDLE ThreadHandle = NULL;
    Status = PsCreateSystemThread(&ThreadHandle, SYNCHRONIZE, NULL, NULL, NULL, &WSKClientFTPFileUpload, (PVOID)Socket);
    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] PsCreateSystemThread failed: 0x%08X.\n",
            Status);

        return Status;
    }

    Status = ObReferenceObjectByHandleWithTag(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, TAG_POOL, (PVOID*)&ClientFTPFileUpload, NULL);
    if (NULL != ThreadHandle)
    {
        ZwClose(ThreadHandle);
        ThreadHandle = NULL;
    }

    if (!NT_SUCCESS(Status))
    {
        CloseWSKClient(SocketFTP, ClientFTPFileUpload);
    }

    return Status;

}

VOID WSKClientFTPFileUpload(_In_ PVOID Context)
{
    NTSTATUS Status = STATUS_SUCCESS;
    SOCKET   Socket = (SOCKET)Context;
    SIZE_T BufferLength = DEFAULT_BUFFER_LEN;
    SIZE_T LoopCount = 0u;
    SIZE_T Bytes = 0u;
    INT    SocketType = 0;

    char Buffer[PAGE_SIZE] = { '\0' };

    Status = WSKConnectPassive(IP_ADDRESS,
                               PORTSTR,
                               AF_INET,
                               SOCK_STREAM);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
    {
        Buffer[Bytes] = '\0';
        if (!NT_SUCCESS(Status))
        {
            DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

            break;
        }

        if (Bytes == 0)
        {
            continue;
        }

        if (strncmp(Buffer, "150", 3) == 0)
            break;
    }

    memset(Buffer, '\0', sizeof(Buffer));

    Bytes = sizeof SocketType;
    Status = WSKGetSocketOpt(Socket, SOL_SOCKET, SO_TYPE, &SocketType, &Bytes);
    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] WSKGetSocketOpt(SO_TYPE) failed: 0x%08X.\n",
            Status);

        return Status;
    }

    ULONG RecvTimeout = 1000u; // ms
    Bytes = sizeof RecvTimeout;
    Status = WSKSetSocketOpt(Socket, SOL_SOCKET, SO_RCVTIMEO, &RecvTimeout, Bytes);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] WSKSetSocketOpt(SO_RCVTIMEO) failed: 0x%08X.\n",
            Status);

        return Status;
    }

    if (SocketType == SOCK_STREAM)
    {
        strcpy(Buffer, "STOR log.txt\r\n");
        Status = WSKSend(Socket, Buffer, strlen(Buffer), &Bytes, 0, NULL, NULL);/* Tell server to change to BINARY mode */

        memset(Buffer, '\0', sizeof(Buffer));

        while ((Status = WSKReceive(Socket, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
        {
            Buffer[Bytes] = '\0';
            if (!NT_SUCCESS(Status))
            {
                DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", Status);

                break;
            }

            if (Bytes == 0)
            {
                continue;
            }

            if (strncmp(Buffer, "150", 3) == 0)
                break;
        }

        memset(Buffer, '\0', sizeof(Buffer));

    }

    WSKFTPSendFile(Socket);
    
    FreeMemory((void*)PORTSTR);
    
    PsTerminateSystemThread(Status);
}

VOID WSKFTPSendFile(SOCKET SocketLocal) //socket
{
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_STANDARD_INFORMATION fileInfo;
    CHAR Buffer[MAXSZ] = { '\0' };
    SIZE_T Bytes = 0u;
    LARGE_INTEGER fileSize = { 0 };
    ULONG temp, temp1, file_size = 0, size, total = 0, down = 1;

    // Prepare Unicode string with the path to the file
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\log.txt");

    // Initialize object attributes
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    NTSTATUS status = ZwCreateFile(&fileHandle,
        GENERIC_READ,   
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,   
        FILE_OPEN,   
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to open file: 0x%X\n", status);
        return;
    }

    // Query file information to get its size
    status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        DbgPrint("Failed to get file information: 0x%X\n", status);
        return;
    }

    // Get the file size
    fileSize = fileInfo.EndOfFile;
    size = (ULONG)fileSize.QuadPart;

    while (size > 0)
    {
        status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, Buffer, MAXSZ, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ZwClose(fileHandle);
            return;
        }

        Bytes = ioStatusBlock.Information;
        file_size += Bytes;
        total = 0;

        while (total < Bytes)
        {
            status = WSKSend(SocketFTP, Buffer, strlen(Buffer), &Bytes, 0, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                ZwClose(fileHandle);
                return;
            }
            total += Bytes;
            memset(Buffer, '\0', sizeof(Buffer));
        }

        size -= Bytes;
    }
    // Close the file handle
    ZwClose(fileHandle);
    
    if (SocketFTP != WSK_INVALID_SOCKET)
    {
        WSKCloseSocket(SocketFTP);

        SocketFTP = WSK_INVALID_SOCKET;
    }
  
    memset(Buffer, '\0', sizeof(Buffer));

    ULONG RecvTimeout = 750000u; // ms
    Bytes = sizeof RecvTimeout;
    status = WSKSetSocketOpt(SocketLocal, SOL_SOCKET, SO_RCVTIMEO, &RecvTimeout, Bytes);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WSK] [Client] WSKSetSocketOpt(SO_RCVTIMEO) failed: 0x%08X.\n",
            status);

        return status;
    }

    while ((status = WSKReceive(SocketLocal, Buffer, DEFAULT_BUFFER_LEN, &Bytes, 0, NULL, NULL)) == 0)
    {
        Buffer[Bytes] = '\0';
        if (!NT_SUCCESS(status))
        {
            DebuggerPrint("[WSK] [Client] WSKReceive2 failed: 0x%08X.\n", status);

            break;
        }

        if (Bytes == 0)
        {
            continue;
        }

        if (strncmp(Buffer, "426", 3) == 0)
            break;
    }

    memset(Buffer, '\0', sizeof(Buffer));

    return status;
}


VOID CloseWSKClient(SOCKET LocalSocket, PETHREAD LocalThread)
{
    if (LocalSocket != WSK_INVALID_SOCKET)
    {
        WSKCloseSocket(LocalSocket);

        LocalSocket = WSK_INVALID_SOCKET;
    }

    if (LocalThread)
    {
        KeWaitForSingleObject(LocalThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObjectWithTag(LocalThread, TAG_POOL);

        LocalThread = NULL;
    }
}