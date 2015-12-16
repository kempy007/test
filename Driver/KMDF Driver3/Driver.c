/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/


/* ########################################
#########   Kempy's Notes  ################
###########################################

hit F7 on solution which will install driver.
right click driver project > debug > step into new instance
request a break.
kd> lm
only nt listed so run
kd> .reload
wait for ages, rerun lm
kd > lm
should list pages of modules.
then set my break points on code view.
f5 to continue
Often have to use debugger commandline to disable breakpoints etc.


windows 8.1 kit includes bcrypt.h, option to explore for hashing functions also referred to as CNG cryptography Next Generation.

to enable debugprints hit a break point and enter
kd>  ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF
continue and all your debug messages will show in the immediate window

use visual studio 2013 community with wdk 8.1 to compile without issues


########## references
https://157.56.75.141/en-us/windows/hardware/ff544652


*/

#include "driver.h"
#include "driver.tmh" //conflicts with stdlib.h

//>>>>>>>>>#### mk added
//#include <bcrypt.h> // for hashing
//#include <stdio.h> // to read in files to byte in order to hash
//#include <minwindef.h> // need for PBYTE
//#include <stdlib.h>
//#include <malloc.h>
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DeviceControl;


#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KMDFDriver3EvtDeviceAdd)
#pragma alloc_text (PAGE, KMDFDriver3EvtDriverContextCleanup)
#endif


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:
    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING( DriverObject, RegistryPath );

    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Register a cleanup callback so that we can call WPP_CLEANUP when
    // the framework driver object is deleted during driver unload.
    //
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = KMDFDriver3EvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config,
                           KMDFDriver3EvtDeviceAdd
                           );

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        //TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

#pragma region Kempy_register_dispatches
	/*##############################################
	###########  Add my own dispatches here ########
	this enables other program to call back this driver and exchange data
	*/
	UNICODE_STRING NtDeviceName;

	PDEVICE_OBJECT Device = NULL;


	//status = IoCreateDeviceSecure(
	//	DriverObject,                 // pointer to driver object
	//	0,                            // device extension size
	//	&NtDeviceName,                // device name
	//	FILE_DEVICE_UNKNOWN,          // device type
	//	0,                            // device characteristics
	//	FALSE, , ,                        // not exclusive
	//	
	//	&Device);                // returned device object pointer

	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}

	//
	// Set dispatch routines.
	//

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	
#pragma endregion

#pragma region kempy_register_callbacks
	/*##############################################
	###########  Add my own callbacks here #########
	this enables the driver to call OS calls each time a process or thread starts
	*/
	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);

	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE); // added  this and driver is getting code 37, access denied. 
	// have created a driver certificate now, which did not help
	// Added to driver properties 'configuration properties' > 'linker' > 'command line', 'additional options' /INTEGRITYCHECK 
	// integritycheck option fixed driver loading error!

	/*##### end section ####
	########################
	*/
#pragma endregion

    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

NTSTATUS
KMDFDriver3EvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. We create and initialize a device object to
    represent a new instance of the device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

	//TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = KMDFDriver3CreateDevice(DeviceInit);

    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}


#pragma region kempy_dispatch_routines
NTSTATUS
DeviceControl(
_In_ PDEVICE_OBJECT DeviceObject,
_Inout_ PIRP Irp
)
/*++
Routine Description:
Dispatches ioctl requests.
Arguments:
DeviceObject - The device object receiving the request.
Irp - The request packet.
Return Value:
Status returned from the method called.
--*/
{
	PIO_STACK_LOCATION IrpStack;
	ULONG Ioctl;
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(DeviceObject);

	Status = STATUS_SUCCESS;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (Ioctl)
	{

	case TD_IOCTL_PROTECT_NAME_CALLBACK:
		Status = DoCallbackSamples(DeviceObject, Irp);
			//;
		break;

	//case IOCTL_REGISTER_CALLBACK:
	//	Status = RegisterCallback(DeviceObject, Irp);
	//	break;

	//case IOCTL_UNREGISTER_CALLBACK:
	//	Status = UnRegisterCallback(DeviceObject, Irp);
	//	break;

	//case IOCTL_GET_CALLBACK_VERSION:
	//	Status = GetCallbackVersion(DeviceObject, Irp);
	//	break;

	default:
		Status = STATUS_FAIL_CHECK; //ErrorPrint("Unrecognized ioctl code 0x%x", Ioctl);
	}

	//
	// Complete the irp and return.
	//

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;

}
#pragma endregion

#pragma region kempy_callback_routines
/*###########################################################
#############  drop in callback routines here  ##############
*/

NTSTATUS DoCallbackSamples(DeviceObject, Irp){
	return STATUS_SUCCESS;
}

VOID CreateProcessNotifyRoutine(IN HANDLE ParentId, IN HANDLE ProcessId, IN BOOLEAN Create) {
	PAGED_CODE();

	DbgPrint("CreateProcessNotifyRoutine called with ParentId = 0x%p %d, ProcessId = 0x%p %d, Create = %d\n",
		ParentId,
		ParentId,
		ProcessId,
		ProcessId,
		Create);
}

VOID CreateProcessNotifyRoutineEx(IN OUT PEPROCESS Process,
								IN HANDLE ProcessId,
								IN OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo) {
	
	PAGED_CODE();

	UNREFERENCED_PARAMETER(CreateInfo);

	if (CreateInfo != NULL)
	{

		DbgPrint(
			
			"CreateProcessNotifyRoutineEx: process %p %d (ID 0x%p %d) created, creator %Ix:%Ix Process:Thread=%d:%d \n"
			"    command line %wZ\n"
			"    file name %wZ (FileOpenNameAvailable: %d)\n",
			Process,
			Process,
			(PVOID)ProcessId,
			(PVOID)ProcessId,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
			(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
			CreateInfo->CommandLine,
			CreateInfo->ImageFileName,
			CreateInfo->FileOpenNameAvailable
			);
	}
	else
	{
		DbgPrint(
			
			"CreateProcessNotifyRoutineEx: process %p %d (ID 0x%p %d) destroyed\n",
			Process,
			Process,
			(PVOID)ProcessId,
			(PVOID)ProcessId
			);
	}

	
	//PPS_CREATE_NOTIFY_INFO CreateInfoCopy = CreateInfo;

	//DbgPrint("CreateProcessNotifyRoutineEx called with Process = 0x%p, ProcessId = 0x%p, Image = \n",
	//	Process,
	//	ProcessId //,
	//	//CreateInfo->ImageFileName
	//	);

	//if (CreateInfoCopy)
	//{
	//	if (CreateInfoCopy->FileOpenNameAvailable == TRUE)
	//	{
	//		DbgPrint(
	//			"PID : 0x%X (%d)  ImageName :%wZ CmdLine : %wZ \n",
	//			ProcessId, ProcessId,
	//			CreateInfoCopy->ImageFileName,
	//			CreateInfoCopy->CommandLine
	//			);
	//	}
	//}
	
}


//>>>>>>>>>>>mk
//VOID HashFileObject()
//{
//	//BYTE rgbMsg[] = readFileBytes()
//
//	static const BYTE rgbMsg[] =
//	{
//		0x61, 0x62, 0x63
//	};
//
//	BCRYPT_ALG_HANDLE       hAlg = NULL;
//	BCRYPT_HASH_HANDLE      hHash = NULL;
//	NTSTATUS                status = STATUS_UNSUCCESSFUL;
//	DWORD                   cbData = 0,
//		cbHash = 0,
//		cbHashObject = 0;
//	PBYTE                   pbHashObject = NULL;
//	PBYTE                   pbHash = NULL;
//
//	//UNREFERENCED_PARAMETER(argc);
//	//UNREFERENCED_PARAMETER(wargv);
//
//	//open an algorithm handle
//	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
//		&hAlg,
//		BCRYPT_SHA256_ALGORITHM,
//		NULL,
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
//		goto Cleanup;
//	}
//
//	//calculate the size of the buffer to hold the hash object
//	if (!NT_SUCCESS(status = BCryptGetProperty(
//		hAlg,
//		BCRYPT_OBJECT_LENGTH,
//		(PBYTE)&cbHashObject,
//		sizeof(DWORD),
//		&cbData,
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
//		goto Cleanup;
//	}
//
//	//allocate the hash object on the heap
//	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
//	if (NULL == pbHashObject)
//	{
//		wprintf(L"**** memory allocation failed\n");
//		goto Cleanup;
//	}
//
//	//calculate the length of the hash
//	if (!NT_SUCCESS(status = BCryptGetProperty(
//		hAlg,
//		BCRYPT_HASH_LENGTH,
//		(PBYTE)&cbHash,
//		sizeof(DWORD),
//		&cbData,
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
//		goto Cleanup;
//	}
//
//	//allocate the hash buffer on the heap
//	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
//	if (NULL == pbHash)
//	{
//		wprintf(L"**** memory allocation failed\n");
//		goto Cleanup;
//	}
//
//	//create a hash
//	if (!NT_SUCCESS(status = BCryptCreateHash(
//		hAlg,
//		&hHash,
//		pbHashObject,
//		cbHashObject,
//		NULL,
//		0,
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
//		goto Cleanup;
//	}
//
//
//	//hash some data
//	if (!NT_SUCCESS(status = BCryptHashData(
//		hHash,
//		(PBYTE)rgbMsg,
//		sizeof(rgbMsg),
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
//		goto Cleanup;
//	}
//
//	//close the hash
//	if (!NT_SUCCESS(status = BCryptFinishHash(
//		hHash,
//		pbHash,
//		cbHash,
//		0)))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
//		goto Cleanup;
//	}
//
//	wprintf(L"Success!\n");
//
//Cleanup:
//
//	if (hAlg)
//	{
//		BCryptCloseAlgorithmProvider(hAlg, 0);
//	}
//
//	if (hHash)
//	{
//		BCryptDestroyHash(hHash);
//	}
//
//	if (pbHashObject)
//	{
//		HeapFree(GetProcessHeap(), 0, pbHashObject);
//	}
//
//	if (pbHash)
//	{
//		HeapFree(GetProcessHeap(), 0, pbHash);
//	}
//}

//char* readFileBytes(const char *name)
//{
//	FILE *fl = fopen(name, "r");
//	fseek(fl, 0, SEEK_END);
//	long len = ftell(fl);
//	char *ret = malloc(len); // example used malloc from? stdlib.h
//	fseek(fl, 0, SEEK_SET);
//	fread(ret, 1, len, fl);
//	fclose(fl);
//	return ret;
//}
//>>>>>>>>>>> end


/*##### end section ####
########################
*/
#pragma endregion

VOID
KMDFDriver3EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE ();

#pragma region Kempy_cleanup_section
	/*####################################################
	###########  cleanup my own callbacks here.  #########
	*/
	PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);

	/*##### end section ####
	########################
	*/
#pragma endregion


    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP( WdfDriverWdmGetDriverObject(DriverObject) );

}
