#pragma once
#include <fltKernel.h>

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

/*
template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
};
*/