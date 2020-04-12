/*++
Author:

    @JagaimoKawaii

Module Name:

    KawaiiFilter.cpp

TODO:

    1- Add the rest of the Registry ops
    2- Add IOCTL to disable FBP (Filter by process)
    3- Research possible "CmCallbackGetKeyObjectID" handle leak



--*/

#include "Common.h"
#include <dontuse.h>
#include "fastmutex.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_PORT FilterPort;
PFLT_PORT SendClientPort;
FastMutex Mutex;
PFLT_FILTER gFilterHandle; 
LARGE_INTEGER gRegHandle;

ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define DRIVER_TAG 'Kawi'

ULONG gTraceFlags = 0;
BOOLEAN FBP = TRUE;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

extern "C" NTSTATUS ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);


/*************************************************************************
    Monitored PIDs stuff
*************************************************************************/

const int MaxPids = 256;
int PidsCount;
ULONG Pids[MaxPids];

bool AddProcess(ULONG pid) {
    for (int i = 0; i < MaxPids; i++) {
        if (Pids[i] == 0) {
            Pids[i] = pid;
            PidsCount++;
            return true;
        }
    }
    return false;
}

bool RemoveProcess(ULONG pid) {
    for (int i = 0; i < MaxPids; i++) {
        if (Pids[i] == pid) {
            Pids[i] = 0;
            PidsCount--;
            return true;
        }
    }
    return false;
}

bool FindProcess(ULONG pid) {
    for (int i = 0; i < MaxPids; i++)
        if (Pids[i] == pid)
            return true;
    return false;
}


/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry ( _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath );

NTSTATUS KawaiiFilterInstanceSetup ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType );

VOID KawaiiFilterInstanceTeardownStart ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags );

VOID KawaiiFilterInstanceTeardownComplete ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags );

NTSTATUS KawaiiFilterUnload ( _In_ FLT_FILTER_UNLOAD_FLAGS Flags );

NTSTATUS KawaiiFilterInstanceQueryTeardown ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags );

FLT_PREOP_CALLBACK_STATUS KawaiiFilterPreOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext );

VOID KawaiiFilterOperationStatusCallback ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot, _In_ NTSTATUS OperationStatus, _In_ PVOID RequesterContext );

FLT_POSTOP_CALLBACK_STATUS KawaiiFilterPostOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags );

FLT_PREOP_CALLBACK_STATUS KawaiiFilterPreOperationNoPostOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext );

BOOLEAN KawaiiFilterDoRequestOperationStatus( _In_ PFLT_CALLBACK_DATA Data );

FLT_PREOP_CALLBACK_STATUS KawaiiPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS KawaiiPreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS KawaiiPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS KawaiiPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
NTSTATUS OnRegistryNotify(PVOID context, PVOID Arg1, PVOID Arg2);


void SendFSRing3Message(UNICODE_STRING* FileName, HANDLE hProcess, USHORT Operation);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KawaiiFilterUnload)
#pragma alloc_text(PAGE, KawaiiFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, KawaiiFilterInstanceSetup)
#pragma alloc_text(PAGE, KawaiiFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, KawaiiFilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, KawaiiPreCreate, nullptr },
    { IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, KawaiiPreRead, nullptr },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, KawaiiPreWrite, nullptr },
    { IRP_MJ_SET_INFORMATION, 0, KawaiiPreSetInformation, nullptr },
    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks
    KawaiiFilterUnload,                           //  MiniFilterUnload
    KawaiiFilterInstanceSetup,                    //  InstanceSetup
    KawaiiFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    KawaiiFilterInstanceTeardownStart,            //  InstanceTeardownStart
    KawaiiFilterInstanceTeardownComplete,         //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

NTSTATUS KawaiiFilterInstanceSetup ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}

NTSTATUS KawaiiFilterInstanceQueryTeardown ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}

VOID KawaiiFilterInstanceTeardownStart ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterInstanceTeardownStart: Entered\n") );
}

VOID KawaiiFilterInstanceTeardownComplete ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterInstanceTeardownComplete: Entered\n") );
}

/*************************************************************************
    Ring3 Communication by port.
*************************************************************************/

_Use_decl_annotations_ NTSTATUS PortConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie) 
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    SendClientPort = ClientPort;
    return STATUS_SUCCESS;
}

void PortDisconnectNotify(PVOID ConnectionCookie) 
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilterHandle, &SendClientPort);
    SendClientPort = nullptr;
}

NTSTATUS PortMessageNotify( PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) 
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS GenericIRPHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) 
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceIOCTLHandler(PDEVICE_OBJECT, PIRP Irp) {

    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto status = STATUS_SUCCESS;
    auto len = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_PROCESS_ADDPID:
        {
            auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
            if (size % sizeof(ULONG) != 0) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }
            auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

            AutoLock<FastMutex> lock(Mutex);
            for (int i = 0; i < size / sizeof(ULONG); i++) {
                auto pid = data[i];
                if (pid == 0) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (FindProcess(pid)) {
                    continue;
                }
                if (PidsCount == MaxPids) {
                    status = STATUS_TOO_MANY_CONTEXT_IDS;
                    break;
                }

                if (!AddProcess(pid)) {
                    status = STATUS_UNSUCCESSFUL;
                }
                len += sizeof(ULONG);
            }
            break;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = len;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry ( _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath )
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER( RegistryPath );
    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES, ("KawaiiFilter!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject, &FilterRegistration, &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    Mutex.Init();
    AddProcess(2);

    if (NT_SUCCESS( status )) {

        // Set IRP Handler
        DriverObject->MajorFunction[IRP_MJ_CREATE] = GenericIRPHandler;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = GenericIRPHandler;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIOCTLHandler;
        // Device creation
        UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\KawaiiDrv");
        PDEVICE_OBJECT DeviceObject;
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
        if (!NT_SUCCESS(status)) 
            KdPrint(("Could not create device object (%08X) \n", status));
        // SynLink creation
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\KawaiiDrv");
        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status)) 
            KdPrint(("Could not create SymLink (%08X) \n", status));
        

        //
        //  Ring 3 communication port   
        //

        UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\FileBackupPort");
        PSECURITY_DESCRIPTOR sd;
        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        OBJECT_ATTRIBUTES attr;
        InitializeObjectAttributes(&attr, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);
        status = FltCreateCommunicationPort(gFilterHandle, &FilterPort, &attr, nullptr, PortConnectNotify, PortDisconnectNotify, PortMessageNotify, 1);
        FltFreeSecurityDescriptor(sd);

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) 
            FltUnregisterFilter( gFilterHandle );
        
        //
        // proces creation/deletion Callback
        //

        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) 
            KdPrint(("Could not create Process Callback (%08X) \n", status));

        //
        // thread creation/deletion Callback
        //

        status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
        if (!NT_SUCCESS(status))
            KdPrint(("failed to set thread callbacks (status=%08X)\n", status));
       
        //
        // registry modification Callback
        //

        UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"7659,224");
        status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &gRegHandle, nullptr);
        if (!NT_SUCCESS(status)) 
            KdPrint(("failed to set registry callback (%08X) \n", status));
        
    }
    KdPrint(("KawaiiFilter loaded"));
    return status;
}

NTSTATUS KawaiiFilterUnload ( _In_ FLT_FILTER_UNLOAD_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterUnload: Entered\n") );

    CmUnRegisterCallback(gRegHandle);
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
    PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
    FltCloseCommunicationPort(FilterPort);
    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS KawaiiFilterPreOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (KawaiiFilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    KawaiiFilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("KawaiiFilter!KawaiiFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID KawaiiFilterOperationStatusCallback ( _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot, _In_ NTSTATUS OperationStatus, _In_ PVOID RequesterContext )
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("KawaiiFilter!KawaiiFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}

FLT_POSTOP_CALLBACK_STATUS KawaiiFilterPostOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS KawaiiFilterPreOperationNoPostOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext )
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN KawaiiFilterDoRequestOperationStatus( _In_ PFLT_CALLBACK_DATA Data )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

// Relevant routines

FLT_PREOP_CALLBACK_STATUS KawaiiPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    const auto& params = Data->Iopb->Parameters.Create;
    BOOLEAN isDel = FALSE;
    if (params.Options & FILE_DELETE_ON_CLOSE) {
        // delete operation
        isDel = TRUE;
    }
   
    if (isDel) {
        SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, NtCurrentProcess(), 4);
    }else{
        SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, NtCurrentProcess(), 0);
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS KawaiiPreRead(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    // set fake content: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-read
    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // what process did this originate from?
    auto process = PsGetThreadProcess(Data->Thread);
    NT_ASSERT(process); // cannot really fail
    HANDLE hProcess;
    auto status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, nullptr, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, hProcess, 1);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;

}

FLT_PREOP_CALLBACK_STATUS KawaiiPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);
    // set fake content: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-write
    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // what process did this originate from?
    auto process = PsGetThreadProcess(Data->Thread);
    NT_ASSERT(process); // cannot really fail
    HANDLE hProcess;
    auto status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, nullptr, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, hProcess, 2);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS KawaiiPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    BOOLEAN isDel = TRUE;
    auto& params = Data->Iopb->Parameters.SetFileInformation;
    if (params.FileInformationClass != FileDispositionInformation &&
        params.FileInformationClass != FileDispositionInformationEx) {
        // not a delete operation
        isDel = FALSE;
    }
 
    auto info = (FILE_DISPOSITION_INFORMATION*)params.InfoBuffer;
    if (!info->DeleteFile)
        isDel = FALSE;

    // what process did this originate from?
    auto process = PsGetThreadProcess(Data->Thread);
    NT_ASSERT(process); // cannot really fail
    HANDLE hProcess;
    auto status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, nullptr, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (isDel) {
        SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, hProcess, 5);
    }else{
        SendFSRing3Message(&Data->Iopb->TargetFileObject->FileName, hProcess, 3);
    }
 
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

void SendFSRing3Message(UNICODE_STRING* FileName, HANDLE hProcess, USHORT Operation) {

    if (SendClientPort && FileName!= nullptr) {

        // Get PID
        auto basicinfo = (PROCESS_BASIC_INFORMATION*)ExAllocatePool(PagedPool, sizeof(PROCESS_BASIC_INFORMATION));
        if (basicinfo == nullptr) {
            KdPrint(("Failed basicinfo allocation\n"));
            return;
        }

        auto status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, basicinfo, sizeof(PROCESS_BASIC_INFORMATION), nullptr);
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed ZwQueryInformationProcess 1\n"));
            ExFreePool(basicinfo);
            return;
        }
        if (FindProcess((ULONG)basicinfo->UniqueProcessId) || !FBP )
        {
            // Get Process Name
            auto size = 300;
            auto processName = (UNICODE_STRING*)ExAllocatePool(PagedPool, size);
            if (processName == nullptr) {
                ExFreePool(basicinfo);
                KdPrint(("Failed processName allocation\n"));
                return;
            }

            RtlZeroMemory(processName, size); // ensure string will be NULL-terminated
            status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, processName, size - sizeof(WCHAR), nullptr);
            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed ZwQueryInformationProcess 2\n"));
                ExFreePool(basicinfo);
                ExFreePool(processName);
                return;
            }

            // Build data struct
            USHORT allocSize = sizeof(KawaiiFSOperation);
            USHORT FileNameSize = 0;
            USHORT ImageSize = 0;

            if (FileName) {
                FileNameSize = FileName->Length;
                allocSize += FileNameSize;
            }

            if (processName) {
                ImageSize = processName->Length;
                allocSize += ImageSize + 4;
            }

            auto msg = (KawaiiFSOperation*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
            RtlZeroMemory(msg, allocSize);
            if (msg == nullptr) {
                ExFreePool(processName);
                ExFreePool(basicinfo);
                KdPrint(("Failed kawaii allocation\n"));
                return;
            }
            KeQuerySystemTime(&msg->Time);
            msg->Type = ItemType::FSactivity;
            msg->ProcessId = basicinfo->UniqueProcessId;
            msg->FileNameLength = FileNameSize / sizeof(WCHAR);
            msg->ProcessLength = ImageSize / sizeof(WCHAR);
            msg->Operation = Operation;

            // Put strings 
            ::memcpy((UCHAR*)msg + sizeof(KawaiiFSOperation), FileName->Buffer, FileNameSize);
            msg->FileName = sizeof(KawaiiFSOperation);

            ::memcpy((UCHAR*)msg + sizeof(KawaiiFSOperation) + FileNameSize + 2, processName->Buffer, ImageSize);
            msg->ProcessName = sizeof(KawaiiFSOperation) + FileNameSize + 2;

            // Send message
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000 * 100; // 100msec
            FltSendMessage(gFilterHandle, &SendClientPort, msg, allocSize, nullptr, nullptr, &timeout);

            ExFreePool(msg);
            ExFreePool(processName);
        }
        
        ExFreePool(basicinfo);
    }
}

/*************************************************************************
    Process callback related stuff.
*************************************************************************/

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);

    if (SendClientPort && (FindProcess(HandleToULong(ProcessId)) || FindProcess(HandleToULong(CreateInfo->ParentProcessId)) || !FBP)) {
        if (CreateInfo ) {
            
            USHORT allocSize = sizeof(ProcessCreateInfo);
            USHORT commandLineSize = 0;
            USHORT ImageSize = 0;

            if (CreateInfo->CommandLine) {
                commandLineSize = CreateInfo->CommandLine->Length;
                allocSize += commandLineSize;
            }

            if (CreateInfo->ImageFileName) {
                ImageSize = CreateInfo->ImageFileName->Length;
                allocSize += ImageSize+4;
            }

            auto item = (ProcessCreateInfo*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
            if (item == nullptr) {
                KdPrint(("Failed allocation\n"));
                return;
            }

            item->ProcessId = HandleToULong(ProcessId);
            item->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
            item->Type = ItemType::ProcessCreate;
            KeQuerySystemTime(&item->Time);


            if (commandLineSize > 0) {
                ::memcpy((UCHAR*)item + sizeof(ProcessCreateInfo), CreateInfo->CommandLine->Buffer, commandLineSize);
                item->CommandLineLength = commandLineSize / sizeof(WCHAR);
                item->CommandLineOffset = sizeof(ProcessCreateInfo);
            }
            else {
                item->CommandLineLength = 0;
            }

            if (ImageSize > 0) {
                ::memcpy((UCHAR*)item + sizeof(ProcessCreateInfo) + commandLineSize+2, CreateInfo->ImageFileName->Buffer, ImageSize);
                item->ImageLength = ImageSize / sizeof(WCHAR);
                item->ImageOffset = sizeof(ProcessCreateInfo) + commandLineSize+2;
            }
            else {
                item->ImageLength = 0;
            }

            // Send message
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000 * 100; // 100msec
            FltSendMessage(gFilterHandle, &SendClientPort, item, allocSize, nullptr, nullptr, &timeout);
            ExFreePool(item);

            // Start nonitoring if parent is being monitored
            if (FindProcess(HandleToULong(CreateInfo->ParentProcessId))) {
                AutoLock<FastMutex> lock(Mutex);
                AddProcess(HandleToULong(ProcessId));
            }

        }
        else {

            
            auto item = (ProcessExitInfo*)ExAllocatePoolWithTag(PagedPool, sizeof(ProcessExitInfo), DRIVER_TAG);
            if (item == nullptr) {
                KdPrint(("Failed allocation\n"));
                return;
            }

            item->Type = ItemType::ProcessExit;
            KeQuerySystemTime(&item->Time);
            item->ProcessId = HandleToULong(ProcessId);

            // Send message
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000 * 100; // 100msec
            FltSendMessage(gFilterHandle, &SendClientPort, item, sizeof(ProcessExitInfo), nullptr, nullptr, &timeout);
            ExFreePool(item);

            if (FindProcess(HandleToULong(ProcessId))) {
                AutoLock<FastMutex> lock(Mutex);
                RemoveProcess(HandleToULong(ProcessId));
            }

        }
    }
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (SendClientPort){
        auto size = sizeof(ThreadCreateExitInfo);
        auto item = (ThreadCreateExitInfo*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
        if (item == nullptr)
            KdPrint(("Failed to allocate memory\n"));
    
        KeQuerySystemTime(&item->Time);
        item->Type = Create ? ItemType::ThreadCreate : ItemType::ThreadExit; 
        item->ProcessId = HandleToULong(ProcessId);
        item->ThreadId = HandleToULong(ThreadId);

        // Send message
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000 * 100; // 100msec
        FltSendMessage(gFilterHandle, &SendClientPort, item, size, nullptr, nullptr, &timeout);
        ExFreePool(item);
    }
}

/*************************************************************************
    Registry callback related stuff.
*************************************************************************/

NTSTATUS OnRegistryNotify(PVOID context, PVOID Arg1, PVOID Arg2) {
    UNREFERENCED_PARAMETER(context);
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-ex_callback_function
    ULONG Curpid = HandleToULong(PsGetCurrentProcessId());
    if (FindProcess(Curpid) || !FBP ){
        switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Arg1) {
            case RegNtPostSetValueKey:
            {
                auto args = (REG_POST_OPERATION_INFORMATION*)Arg2;
                if (!NT_SUCCESS(args->Status))
                    break;

                PCUNICODE_STRING name;
                // ME PREOCUPA QUE NO HAY API PARA LIBERAR LA KEY EN WINDOWS 7, ESTOY LEAKEANDO UN HANDLE??
                if (NT_SUCCESS(CmCallbackGetKeyObjectID(&gRegHandle, args->Object, nullptr, &name))) {
                    auto preInfo = (REG_SET_VALUE_KEY_INFORMATION*)args->PreInformation;
                    NT_ASSERT(preInfo);
                    USHORT size = sizeof(RegistrySetValueInfo);
                    auto item = (RegistrySetValueInfo*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
                    if (item == nullptr || preInfo == nullptr)
                        break;

                    RtlZeroMemory(item, size);

                    KeQuerySystemTime(&item->Time);
                    item->Type = ItemType::RegistrySetValue;

                    // get client Pid/Tid 
                    item->ProcessId = Curpid;
                    item->ThreadId = HandleToULong(PsGetCurrentThreadId());

                    // get specific key/value data
                    ::wcsncpy_s(item->KeyName, name->Buffer, name->Length / sizeof(WCHAR) - 1);
                    ::wcsncpy_s(item->ValueName, preInfo->ValueName->Buffer, preInfo->ValueName->Length / sizeof(WCHAR) - 1);

                    item->DataType = preInfo->Type;
                    item->DataSize = preInfo->DataSize;
                    ::memcpy(item->Data, preInfo->Data, min(item->DataSize, sizeof(item->Data)));

                    // Send message
                    LARGE_INTEGER timeout;
                    timeout.QuadPart = -10000 * 100; // 100msec
                    FltSendMessage(gFilterHandle, &SendClientPort, item, size, nullptr, nullptr, &timeout);
                    ExFreePool(item);
                }
                break;
            }
            case RegNtPostQueryValueKey:
            {
                auto args = (REG_POST_OPERATION_INFORMATION*)Arg2;
                if (!NT_SUCCESS(args->Status)) {
                    break;
                }
                break;
            }
            case RegNtPostCreateKey:
            {
                auto args = (REG_POST_CREATE_KEY_INFORMATION*)Arg2;
                if (!NT_SUCCESS(args->Status)) {
                    break;
                }
                break;
            }
            default:
                break;
        }
    }
    return STATUS_SUCCESS;
}
