# FTP Connection and File Transfer in Windows Kernel Driver

🔌📁 This project includes a command to establish an FTP connection and send files in a Windows kernel driver development environment. The project communicates over Windows Sockets (Winsock) using the libwsk library.

## Requirements

- Windows operating system
- Visual Studio development environment
- libwsk library

## Installation

1. Clone the project:

    ```bash
    git clone https://github.com/CaptanMoss/kernel_ftp.git
    ```

2. Open the project with Visual Studio.

3. Add the libwsk library to your project and configure it if necessary.

4. Build your project.

## Usage

1. Install the compiled driver on your system.

2. Run the command to establish an FTP connection and send files:

    ```bash
    ftp.exe ftp.server.com 21
    ```

## Example Code

```c
#include <ntddk.h>
#include <wsk.h>

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

```
# FTP Commands

| Command | Description                                 | State |
|---------|---------------------------------------------|-------|
| USER    | Used to log in to the FTP server with a specific username. | Active |
| PASS    | Used to send the password for a specific user to the server. | Active |
| PASV    | Used to switch the FTP server into passive mode. | Active |
| PWD     | Used to display the current working directory. | Passive |
| CWD     | Used to change the working directory. | Passive |
| LIST    | Used to list the files and directories on the server. | Passive |
| RETR    | Used to download a specific file from the server. | Passive |
| STOR    | Used to upload a file to the server. | Active |
| DELE    | Used to delete a file from the server. | Passive |
| MKD     | Used to create a new directory. | Passive |
| RMD     | Used to remove a directory. | Passive |
| SYST    | Used to determine the server's operating system. | Passive |
| QUIT    | Used to exit the FTP session. | Passive |

## Demo

![](2024-05-09-12-06-21.gif)

## Contributing

🤝 If you'd like to contribute to this project, please open a pull request or create an issue to discuss your suggestions.

## Community Support for Additional FTP Commands

🌐 In order to implement additional FTP commands, I rely on community support. If you have specific FTP commands you'd like to see implemented, feel free to contribute or discuss them with me in the issues section.

## References

📚 For a comprehensive reference on FTP commands and the FTP protocol, please refer to the [RFC 959](https://datatracker.ietf.org/doc/html/rfc959) document.

