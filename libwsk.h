#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntddkbd.h>
#include <wsk.h>
#include <ntstrsafe.h>

#define XOR_KEY 0xBF
const ULONG  TAG_POOL = 'TSET'; // TEST


unsigned int CharToHex(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

// Verilen char stringini hexadecimal forma dönüştüren fonksiyon
unsigned char* CharStringToHex(const char* charString) {
    // Char stringinin uzunluğunu hesapla
    unsigned long length = strlen(charString);

    // Bellek tahsisi için gerekli buffer boyutunu hesapla
    unsigned long hexDataLength = length / 2;
    unsigned char* hexData = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, (hexDataLength + 1) * sizeof(unsigned char), TAG_POOL);
    if (hexData == NULL) {
        return NULL;
    }

    // Char stringini hex veriye dönüştür
    for (unsigned long i = 0; i < hexDataLength; i++) {
        hexData[i] = (CharToHex(charString[2 * i]) << 4) | CharToHex(charString[2 * i + 1]);
    }
    hexData[hexDataLength] = '\0';

    for (unsigned long i = 0; i < hexDataLength; i++) {
        hexData[i] = hexData[i] ^ XOR_KEY; // XOR işlemi
    }

    return hexData;
}


// ASCII karakteri hexadecimal forma dönüştürür
ULONG AsciiToHex(WCHAR ascii) {
    if (ascii >= L'0' && ascii <= L'9') {
        return ascii - L'0';
    }
    else if (ascii >= L'a' && ascii <= L'f') {
        return ascii - L'a' + 10;
    }
    else if (ascii >= L'A' && ascii <= L'F') {
        return ascii - L'A' + 10;
    }
    return 0;
}

// Verilen ASCII stringini hexadecimal forma dönüştürür
VOID AsciiStringToHex(PCSTR asciiString, UCHAR* hexData, ULONG length) {
    for (ULONG i = 0; i < length; i++) {
        WCHAR highNibble = asciiString[2 * i];
        WCHAR lowNibble = asciiString[2 * i + 1];
        hexData[i] = (AsciiToHex(highNibble) << 4) | AsciiToHex(lowNibble);
    }
    hexData[length] = '\0';
}

// Verilen veriyi belirli bir anahtar ile XOR işlemine tabi tutar
VOID XorOperation(UCHAR* data, ULONG length, UCHAR key) {
    for (ULONG i = 0; i < length; i++) {
        data[i] ^= key;
    }
    data[length] = '\0';
}

// UCHAR* dizisini PCWSTR'ye dönüştüren fonksiyon
PCWSTR ConvertUcharToPcwstr(const UCHAR* ucharData, ULONG ucharLength) {
    // Buffer boyutunu hesapla (her karakter için 2 byte)
    ULONG bufferSize = (ucharLength + 1) * sizeof(WCHAR);

    // Buffer için bellek tahsisi
    WCHAR* buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'UC2W');
    if (buffer == NULL) {
        return NULL; // Bellek tahsisi başarısız oldu
    }

    // Her bir ASCII karakterini tek bir UNICODE karakterine dönüştür
    for (ULONG i = 0; i < ucharLength; i++) {
        buffer[i] = (WCHAR)ucharData[i];
    }

    // Null karakterle sonlandır
    buffer[ucharLength] = L'\0';

    return buffer;
}


UCHAR* DeobfuscationString(PCSTR asciiString) {

    ULONG asciiStringLength = strlen(asciiString);
    ULONG hexDataLength = (asciiStringLength / 2) + 10;
    UCHAR* hexData = ExAllocatePoolWithTag(NonPagedPool, hexDataLength, TAG_POOL);

    memset(hexData, '\0', hexDataLength * sizeof(UCHAR));

    if (hexData == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AsciiStringToHex(asciiString, hexData, hexDataLength);


    XorOperation(hexData, (asciiStringLength / 2), XOR_KEY);

    return hexData;
}


LPCWSTR ConvertUcharToLpcwstr(UCHAR* ucharString) {
    UNICODE_STRING unicodeString;
    RtlInitUnicodeString(&unicodeString, NULL);

    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, ucharString);
    RtlAnsiStringToUnicodeString(&unicodeString, &ansi, TRUE);

    return (LPCWSTR)unicodeString.Buffer;
}

typedef UINT_PTR SOCKET;

#ifndef WSK_INVALID_SOCKET
#  define WSK_INVALID_SOCKET        ((SOCKET)(~0))
#endif

#ifndef WSK_FLAG_INVALID_SOCKET
#    define WSK_FLAG_INVALID_SOCKET ((ULONG)0xffffffff)
#endif

#ifndef WSK_FLAG_STREAM_SOCKET
#   define WSK_FLAG_STREAM_SOCKET   ((ULONG)0x00000008)
#endif

typedef struct _WSKOVERLAPPED
{
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            ULONG Offset;
            ULONG OffsetHigh;
        } DUMMYSTRUCTNAME;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    KEVENT Event;
}WSKOVERLAPPED, *PWSKOVERLAPPED;
typedef const WSKOVERLAPPED* PCWSKOVERLAPPED;

typedef VOID(WSKAPI* LPWSKOVERLAPPED_COMPLETION_ROUTINE)(
    _In_ NTSTATUS       Status,
    _In_ ULONG_PTR      Bytes,
    _In_ WSKOVERLAPPED* Overlapped
    );

/* WSK Socket function prototypes */

#ifdef __cplusplus
extern "C" {
#endif

VOID WSKAPI WSKSetLastError(
    _In_ NTSTATUS Status
);

NTSTATUS WSKAPI WSKGetLastError();

typedef struct _WSKDATA
{
    UINT16 HighestVersion;
    UINT16 LowestVersion;
}WSKDATA, *PWSKDATA;
typedef const WSKDATA* PCWSKDATA;

NTSTATUS WSKAPI WSKStartup(
    _In_  UINT16   Version,
    _Out_ WSKDATA* WSKData
);

VOID WSKAPI WSKCleanup();

VOID WSKAPI WSKCreateEvent(
    _Out_ KEVENT* Event
);

NTSTATUS WSKAPI WSKGetOverlappedResult(
    _In_  SOCKET         Socket,
    _In_  WSKOVERLAPPED* Overlapped,
    _Out_opt_ SIZE_T*    TransferBytes,
    _In_  BOOLEAN        Wait
);

NTSTATUS WSKAPI WSKGetAddrInfo(
    _In_opt_ LPCWSTR        NodeName,
    _In_opt_ LPCWSTR        ServiceName,
    _In_     UINT32         Namespace,
    _In_opt_ GUID*          Provider,
    _In_opt_ PADDRINFOEXW   Hints,
    _Outptr_result_maybenull_ PADDRINFOEXW*  Result,
    _In_opt_ UINT32         TimeoutMilliseconds,
    _In_opt_ WSKOVERLAPPED* Overlapped,
    _In_opt_ LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);

VOID WSKAPI WSKFreeAddrInfo(
    _In_ PADDRINFOEXW Data
);

NTSTATUS WSKAPI WSKGetNameInfo(
    _In_ const SOCKADDR*  Address,
    _In_ ULONG      AddressLength,
    _Out_writes_opt_(NodeNameSize)      LPWSTR  NodeName,
    _In_ ULONG      NodeNameSize,
    _Out_writes_opt_(ServiceNameSize)   LPWSTR  ServiceName,
    _In_ ULONG      ServiceNameSize,
    _In_ ULONG      Flags
);

#define WSK_MAX_ADDRESS_STRING_LENGTH ((UINT32)64u)

NTSTATUS WSKAPI WSKAddressToString(
    _In_reads_bytes_(AddressLength) SOCKADDR* SockAddress,
    _In_    UINT32  AddressLength,
    _Out_writes_to_(*AddressStringLength, *AddressStringLength) LPWSTR AddressString,
    _Inout_ UINT32* AddressStringLength
);

NTSTATUS WSKAPI WSKStringToAddress(
    _In_    PCWSTR      AddressString,
    _Inout_ SOCKADDR*   SockAddress,    // must init Address->si_family
    _Inout_ UINT32*     AddressLength
);

NTSTATUS WSKAPI WSKSocket(
    _Out_ SOCKET*           Socket,
    _In_  ADDRESS_FAMILY    AddressFamily,
    _In_  USHORT            SocketType,
    _In_  ULONG             Protocol,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSTATUS WSKAPI WSKCloseSocket(
    _In_ SOCKET Socket
);

NTSTATUS WSKAPI WSKIoctl(
    _In_ SOCKET         Socket,
    _In_ ULONG          ControlCode,
    _In_reads_bytes_opt_(InputSize)     PVOID InputBuffer,
    _In_ SIZE_T         InputSize,
    _Out_writes_bytes_opt_(OutputSize)  PVOID OutputBuffer,
    _In_ SIZE_T         OutputSize,
    _Out_opt_ SIZE_T*   OutputSizeReturned,
    _In_opt_  WSKOVERLAPPED* Overlapped,
    _In_opt_  LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);

NTSTATUS WSKAPI WSKSetSocketOpt(
    _In_ SOCKET         Socket,
    _In_ ULONG          OptionLevel,    // SOL_xxxx
    _In_ ULONG          OptionName,     // SO_xxxx
    _In_reads_bytes_(InputSize)     PVOID InputBuffer,
    _In_ SIZE_T         InputSize
);

NTSTATUS WSKAPI WSKGetSocketOpt(
    _In_ SOCKET         Socket,
    _In_ ULONG          OptionLevel,    // SOL_xxxx
    _In_ ULONG          OptionName,     // SO_xxxx
    _Out_writes_bytes_(*OutputSize) PVOID OutputBuffer,
    _Inout_ SIZE_T*     OutputSize
);

NTSTATUS WSKAPI WSKBind(
    _In_ SOCKET         Socket,
    _In_ PSOCKADDR      LocalAddress,
    _In_ SIZE_T         LocalAddressLength
);

NTSTATUS WSKAPI WSKAccept(
    _In_  SOCKET        Socket,
    _Out_ SOCKET*       SocketClient,
    _Out_opt_ PSOCKADDR LocalAddress,
    _In_ SIZE_T         LocalAddressLength,
    _Out_opt_ PSOCKADDR RemoteAddress,
    _In_ SIZE_T         RemoteAddressLength
);

NTSTATUS WSKAPI WSKListen(
    _In_ SOCKET         Socket,
    _In_ INT            BackLog
);

NTSTATUS WSKAPI WSKConnect(
    _In_ SOCKET         Socket,
    _In_ PSOCKADDR      RemoteAddress,
    _In_ SIZE_T         RemoteAddressLength
);

NTSTATUS WSKAPI WSKDisconnect(
    _In_ SOCKET         Socket,
    _In_ ULONG          Flags
);

NTSTATUS WSKAPI WSKSend(
    _In_ SOCKET         Socket,
    _In_ PVOID          Buffer,
    _In_ SIZE_T         BufferLength,
    _Out_opt_ SIZE_T*   NumberOfBytesSent,
    _In_ ULONG          Flags,
    _In_opt_  WSKOVERLAPPED* Overlapped,
    _In_opt_  LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);

NTSTATUS WSKAPI WSKSendTo(
    _In_ SOCKET         Socket,
    _In_ PVOID          Buffer,
    _In_ SIZE_T         BufferLength,
    _Out_opt_ SIZE_T*   NumberOfBytesSent,
    _Reserved_ ULONG    Flags,
    _In_opt_ PSOCKADDR  RemoteAddress,
    _In_ SIZE_T         RemoteAddressLength,
    _In_opt_  WSKOVERLAPPED* Overlapped,
    _In_opt_  LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);

NTSTATUS WSKAPI WSKReceive(
    _In_ SOCKET         Socket,
    _In_ PVOID          Buffer,
    _In_ SIZE_T         BufferLength,
    _Out_opt_ SIZE_T*   NumberOfBytesRecvd,
    _In_ ULONG          Flags,
    _In_opt_  WSKOVERLAPPED* Overlapped,
    _In_opt_  LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);
/*
int WSAAPI WSARecv(
  [in]      SOCKET                             s,
  [in, out] LPWSABUF                           lpBuffers,
  [in]      DWORD                              dwBufferCount,
  [out]     LPDWORD                            lpNumberOfBytesRecvd,
  [in, out] LPDWORD                            lpFlags,
  [in]      LPWSAOVERLAPPED                    lpOverlapped,
  [in]      LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
*/

NTSTATUS WSKAPI WSKReceiveFrom(
    _In_ SOCKET         Socket,
    _In_ PVOID          Buffer,
    _In_ SIZE_T         BufferLength,
    _Out_opt_ SIZE_T*   NumberOfBytesRecvd,
    _Reserved_ ULONG    Flags,
    _Out_opt_ PSOCKADDR RemoteAddress,
    _In_ SIZE_T         RemoteAddressLength,
    _In_opt_  WSKOVERLAPPED* Overlapped,
    _In_opt_  LPWSKOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine
);

#ifdef __cplusplus
}
#endif
