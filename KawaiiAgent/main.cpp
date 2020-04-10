#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <string>


#pragma comment(lib, "fltlib")

enum class ItemType : short {
	None,
	FSactivity,
	ProcessCreate,
	ProcessExit,
	RegistrySetValue
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

template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
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
		case ItemType::RegistrySetValue:
		{
			auto msg = (KawaiiFSOperation*)buffer;
			std::wstring filename((WCHAR*)(buffer + msg->FileName), msg->FileNameLength + 1);
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
	}
}
int main() {
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

	return 0;
}