/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriver3,
    0x159c4750,0x7123,0x4e0c,0x9a,0x84,0xfb,0x4d,0x71,0x78,0xeb,0xe1);
// {159c4750-7123-4e0c-9a84-fb4d7178ebe1}
