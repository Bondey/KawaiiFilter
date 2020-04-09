#include <Windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <string>


#pragma comment(lib, "fltlib")

struct KawaiiFSOperation {
	USHORT Operation;
	USHORT FileNameLength;
	WCHAR FileName[1];
};

void HandleMessage(const BYTE* buffer) {
	auto msg = (KawaiiFSOperation*)buffer;
	std::wstring filename(msg->FileName, msg->FileNameLength);


	switch (msg->Operation) {
		case 0:
			printf("file Open: %ws\n", filename.c_str());
			break;
		case 1:
			printf("file Read: %ws\n", filename.c_str());
			break;
		case 2:
			printf("file Write: %ws\n", filename.c_str());
			break;
		case 3:
			printf("file SetInfo: %ws\n", filename.c_str());
			break;
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