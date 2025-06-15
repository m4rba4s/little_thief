#ifndef EVASION_H
#define EVASION_H

#include "common_defines.h"

// Restores the .text section of ntdll.dll in memory from a clean copy on disk.
BOOL unhook_ntdll();

// Patches common monitoring functions like AmsiScanBuffer and EtwEventWrite.
BOOL patch_monitoring_functions();


#endif // EVASION_H 