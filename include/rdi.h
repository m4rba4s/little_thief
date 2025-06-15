#ifndef RDI_H
#define RDI_H

#include "common_defines.h"
#include "rtldr_ctx.h"

// Function to invoke the ReflectiveLoader export from a DLL buffer
NTSTATUS InvokeReflectiveLoader(
    PRTLDR_CTX ctx,
    PBYTE pPayloadBuffer, 
    LPCSTR reflectiveLoaderFunctionName, 
    LPVOID pParameter
);

#endif // RDI_H 