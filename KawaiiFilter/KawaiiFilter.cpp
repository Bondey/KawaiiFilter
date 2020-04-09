/*++

Module Name:

    KawaiiFilter.cpp

Abstract:

    This is the main module of the KawaiiFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

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

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_READ,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      KawaiiFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      KawaiiFilterPreOperation,
      KawaiiFilterPostOperation },

#endif // TODO

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
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS DriverEntry ( _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS KawaiiFilterUnload ( _In_ FLT_FILTER_UNLOAD_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("KawaiiFilter!KawaiiFilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
KawaiiFilterPreOperation ( _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext )
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
