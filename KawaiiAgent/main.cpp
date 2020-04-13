#include "Common.h"
#include <fltUser.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>

#pragma comment(lib, "fltlib")

WCHAR Hprocs[50][100];
int nhprocs = 0;
WCHAR Kprocs[50][100];
int nkprocs = 0;

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
		/*case ItemType::FSactivity:
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
		} */
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
		case ItemType::RegistryKeyInfo:
		{
			DisplayTime(header->Time);
			auto info = (RegistryKeyInfo*)buffer;
			switch (info->Operation){
				case 1:
					printf("Registry Open Key %ws BY: %d \n", info->KeyName, info->ProcessId);
					break;
				case 2:
					printf("Registry Create Key %ws BY: %d \n", info->KeyName, info->ProcessId);
					break;
				case 3:
					printf("Registry Rename Key %ws BY: %d \n", info->KeyName, info->ProcessId);
					break;
				case 4:
					printf("Registry Query value Key %ws BY: %d \n", info->KeyName, info->ProcessId);
					break;
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

void readConfig() {
	std::wstring line;
	std::wifstream myfile;
	BOOLEAN shprocs = FALSE;
	BOOLEAN skprocs = FALSE;
	myfile.open("Kawaii.conf");
	if (myfile.is_open())
	{
		while (getline(myfile, line))
		{
			if (wcsstr(line.c_str(), L"[HProc]")){
				shprocs = TRUE;
				skprocs = FALSE;
			}
			else if (wcsstr(line.c_str(), L"[KProc]")) {
				shprocs = FALSE;
				skprocs = TRUE;
			}
			else if (shprocs && nhprocs < 50 ) {
				::wcsncpy_s(Hprocs[nhprocs], line.c_str(), 100);
				nhprocs++;
			}else if (skprocs && nkprocs < 50) {
				::wcsncpy_s(Kprocs[nkprocs], line.c_str(), 100);
				nkprocs++;
			}	
		}
	}
	myfile.close();
	auto hfile = ::CreateFile(L"\\\\.\\KawaiiDrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	DWORD bytes;

	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Could not get the driver Handle\n");
		DWORD bytes = GetLastError();
		printf("Got Error: %d\n", bytes);
		return;
	}
	for (int i = 0; i < nhprocs; i++) {
		::DeviceIoControl(hfile, IOCTL_HIDE_IMAGE, Hprocs[i], lstrlenW(Hprocs[i])*sizeof(WCHAR), nullptr, 0, &bytes, nullptr);
	}
	for (int i = 0; i < nkprocs; i++) {
		::DeviceIoControl(hfile, IOCTL_KILL_IMAGE, Kprocs[i], lstrlenW(Kprocs[i]) * sizeof(WCHAR), nullptr, 0, &bytes, nullptr);
	}
}

int wmain(int argc, const wchar_t* argv[]) {

	readConfig();
	/*
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
		::DeviceIoControl(hfile, IOCTL_TOGGLE_FBP, nullptr, 0, nullptr, 0, &bytes, nullptr);
		if (!::_wcsicmp(argv[1], L"-t")) {
			::DeviceIoControl(hfile, IOCTL_TOGGLE_FBP, nullptr, 0, nullptr, 0, &bytes, nullptr);
		} else{
			ULONG pid = ::_wtoi(argv[1]);
			printf("Adding %d PID \n", pid);

			::DeviceIoControl(hfile, IOCTL_PROCESS_ADDPID, &pid, sizeof(ULONG), nullptr, 0, &bytes, nullptr);
		}
	}
	*/
	return 0;
}