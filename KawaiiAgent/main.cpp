#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <string>


#pragma comment(lib, "fltlib")

#define IOCTL_PROCESS_ADDPID CTL_CODE(0x8000,0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TOGGLE_FBP CTL_CODE(0x8000,0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum class ItemType : short {
	None,
	FSactivity,
	ProcessCreate,
	ProcessExit,
	RegistrySetValue,
	ThreadCreate,
	ThreadExit,
	ImageLoad,
	OpenProcess
};

struct ItemHeader {
	ItemType Type;
	LARGE_INTEGER Time;
};

struct KawaiiFSOperation : ItemHeader {
	USHORT Operation;
	ULONG_PTR ProcessId;
	USHORT FileNameLength;
	USHORT ProcessLength;
	USHORT FileName;
	USHORT ProcessName;
};

struct ProcessExitInfo : ItemHeader {
	ULONG ProcessId;
};

struct ProcessCreateInfo : ItemHeader {
	ULONG ProcessId;
	ULONG ParentProcessId;
	USHORT CommandLineLength;
	USHORT ImageLength;
	USHORT CommandLineOffset;
	USHORT ImageOffset;
};

struct RegistrySetValueInfo : ItemHeader {
	ULONG ProcessId;
	ULONG ThreadId;
	WCHAR KeyName[256];
	WCHAR ValueName[64];
	ULONG DataType;
	UCHAR Data[128];
	ULONG DataSize;
};

struct ThreadCreateExitInfo : ItemHeader {
	BOOLEAN remote;
	ULONG ThreadId;
	ULONG CreatorProcessId;
	ULONG TargetProcessId;
};

struct ImageLoadInfo : ItemHeader {
	ULONG ProcessId;
	USHORT ImageLength;
	USHORT ImageOffset;
};

struct OpenProcessInfo : ItemHeader {
	ULONG OpenerProces;
	ULONG TargetProcess;
};

void DisplayTime(const LARGE_INTEGER& time) {
	SYSTEMTIME st;
	::FileTimeToSystemTime((FILETIME*)&time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayBinary(const UCHAR* buffer, DWORD size) {
	for (DWORD i = 0; i < size; i++)
		printf("%02X ", buffer[i]);

	printf("\n");
}

void HandleMessage(const BYTE* buffer) {
	auto header = (ItemHeader*)buffer;
	switch (header->Type) {
		case ItemType::FSactivity:
		{
			auto msg = (KawaiiFSOperation*)buffer;
			USHORT totallen = (USHORT)msg->FileNameLength + 1;
			std::wstring filename((WCHAR*)(buffer + msg->FileName),totallen);
			filename[msg->FileNameLength] = 0;
			std::wstring Procname((WCHAR*)(buffer + msg->ProcessName), msg->ProcessLength);
			DisplayTime(header->Time);
			switch (msg->Operation) {
				case 0:
					printf("file Open: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
				case 1:
					printf("file Read: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
				case 2:
					printf("file Write: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
				case 3:
					printf("file SetInfo: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
				case 4:
					printf("file Delete with Openf: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
				case 5:
					printf("fileDelete with SetInfo: %ws\n", filename.c_str());
					printf("\tBy process: %ws with PID %I64d\n", Procname.c_str(), msg->ProcessId);
					break;
			}
			break;
		}
		case ItemType::ProcessExit:
		{
			DisplayTime(header->Time);
			auto info = (ProcessExitInfo*)buffer;
			printf("Process %d Exited\n",info->ProcessId);
			break;
		}
		case ItemType::ProcessCreate:
		{
			DisplayTime(header->Time);
			auto info = (ProcessCreateInfo*)buffer;
			std::wstring commandline((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
			std::wstring image((WCHAR*)(buffer + info->ImageOffset), info->ImageLength);
			printf("Process %d Created\n.", info->ProcessId);
			printf(" Image: %ws\n", image.c_str());
			printf("\tComandline: %ws\n\n", commandline.c_str());
			break;
		}
		case ItemType::RegistrySetValue:
		{
			DisplayTime(header->Time);
			auto info = (RegistrySetValueInfo*)buffer;
			printf("Registry write PID=%d: %ws\\%ws type: %d size: %d data: ", info->ProcessId, info->KeyName, info->ValueName, info->DataType, info->DataSize);
			switch (info->DataType) {
				case REG_DWORD:
				{
					printf("0x%08X\n", *(DWORD*)info->Data);
					break;
				}
				case REG_SZ:
				case REG_EXPAND_SZ:
				{
					printf("%ws\n", (WCHAR*)info->Data);
					break;
				}
				case REG_BINARY:
				{
					DisplayBinary(info->Data, min(info->DataSize, sizeof(info->Data)));
					break;
				}
				default:
				{
					DisplayBinary(info->Data, min(info->DataSize, sizeof(info->Data)));
					break;
				}
			}
			break;
		}
		case ItemType::ThreadCreate:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Created in process %d from process %d\n",
				info->ThreadId, info->TargetProcessId, info->CreatorProcessId);
			break;
		}
		case ItemType::ThreadExit:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Exited from process %d\n",
				info->ThreadId, info->TargetProcessId);
			break;
		}
		case ItemType::ImageLoad:
		{
			DisplayTime(header->Time);
			auto info = (ImageLoadInfo*)buffer;
			std::wstring image((WCHAR*)(buffer + info->ImageOffset), info->ImageLength);
			printf("Process %d Loaded image %ws\n.", info->ProcessId, image.c_str());
			break;
		}
		case ItemType::OpenProcess:
		{
			DisplayTime(header->Time);
			auto info = (OpenProcessInfo*)buffer;
			printf("Process %d got handle for process %d\n",
				info->OpenerProces, info->TargetProcess);
			break;
		}
	}
}

int wmain(int argc, const wchar_t* argv[]) {
	if (argc < 2) {
		HANDLE hPort;
		auto hr = ::FilterConnectCommunicationPort(L"\\FileBackupPort", 0, nullptr, 0, nullptr, &hPort);
		if (FAILED(hr)) {
			printf("Error connecting to port (HR=0x%08X)\n", hr);
			return 1;
		}

		BYTE buffer[1 << 12];	// 4 KB
		auto message = (FILTER_MESSAGE_HEADER*)buffer;

		for (;;) {
			hr = ::FilterGetMessage(hPort, message, sizeof(buffer), nullptr);
			if (FAILED(hr)) {
				printf("Error receiving message (0x%08X)\n", hr);
				break;
			}
			HandleMessage(buffer + sizeof(FILTER_MESSAGE_HEADER));
		}

		::CloseHandle(hPort);
	}
	else {

		auto hfile = ::CreateFile(L"\\\\.\\KawaiiDrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		DWORD bytes;

		if (hfile == INVALID_HANDLE_VALUE) {
			printf("Could not get the driver Handle\n");
			DWORD bytes = GetLastError();
			printf("Got Error: %d\n",bytes);
			return 1;
		}

		if (!::_wcsicmp(argv[1], L"-t")) {
			::DeviceIoControl(hfile, IOCTL_TOGGLE_FBP, nullptr, 0, nullptr, 0, &bytes, nullptr);
		} else{
			ULONG pid = ::_wtoi(argv[1]);
			printf("Adding %d PID \n", pid);

			::DeviceIoControl(hfile, IOCTL_PROCESS_ADDPID, &pid, sizeof(ULONG), nullptr, 0, &bytes, nullptr);
		}
	}
	return 0;
}