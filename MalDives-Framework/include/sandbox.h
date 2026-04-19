#pragma once

#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <psapi.h>
#include "nt_defs.h"

// Linker instructions for required libraries
#pragma comment(lib, "Shlwapi.lib")

// Detecting Virtual Machine ----------------------------------------------------------------------------------------------------------------

 // Checks if the executable name contains more than 3 digits (common in sandboxes)
BOOL ExeDigitsInNameCheck();

// Checks hardware specs (CPU cores, RAM size, and USB history) to detect virtual environments
BOOL IsVenvByHardwareCheck();

// Checks if the monitor resolution matches common user setups
BOOL CheckMachineResolution();

// Callback used by EnumDisplayMonitors within CheckMachineResolution
BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata);

// Checks if the total number of running processes is suspiciously low
BOOL CheckMachineProcesses();


// Time Fast-Forwarding  ----------------------------------------------------------------------------------------------------------

/*
 * Delay Execution Techniques
 * Examples for the 'ftMinutes' parameter:
 * - 1.5 : 1 minute and 30 seconds
 * - 0.5 : 30 seconds
 * - 1.0 : 1 minute
 * - 0.1 : 6 seconds
 */

 // tech 1: using NtDelayExecution
BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes);

// tech 2: using WaitForSingleObject
BOOL DelayExecutionVia_WFSO(FLOAT ftMinutes);

// tech 3: using MsgWaitForMultipleObjectsEx
BOOL DelayExecutionVia_MWFMOEx(FLOAT ftMinutes);

// tech 4: using NtWaitForSingleObject
BOOL DelayExecutionVia_NtWFSO(FLOAT ftMinutes);



// API Hammering

// this function will wait more than dwSec by one second or more 
int ApiHammering(DWORD dwSec); 

HANDLE AsyncApiHammering();
