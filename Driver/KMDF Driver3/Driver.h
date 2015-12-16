/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#define INITGUID

#include <ntddk.h>
#include <wdf.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KMDFDriver3EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP KMDFDriver3EvtDriverContextCleanup;

#pragma region kempy_declare_functions
/*##############################################
###########  Declare Functions #########
*/
#define TD_IOCTL_PROTECT_NAME_CALLBACK        CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 2), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS		DoCallbackSamples(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID     CreateProcessNotifyRoutine(IN HANDLE ParentId, IN HANDLE ProcessId, IN BOOLEAN Create);
VOID     CreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId,
	IN OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID	HashFileObject();
char* readFileBytes(const char *name);
/*##### end section ####
########################
*/
#pragma endregion
