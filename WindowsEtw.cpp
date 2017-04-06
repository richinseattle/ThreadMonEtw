/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver
*  Filename: WindowsEtw.cpp
*  Implement the communication with the Windows ETW
*  Last revision: 12/01/2016
*
*  Copyright© 2016 Andrea Allievi, Richard Johnson
*  Microsoft Ltd & TALOS Research and Intelligence Group
*  All right reserved
**********************************************************************/
#include "stdafx.h"
#include "WindowsEtw.h"
#include <Evntrace.h>
#include <Evntcons.h>
#include <crtdbg.h>
#include <tlhelp32.h>
#pragma comment(lib, "tdh.lib")

int g_iNumOfThreads = 0;
DWORD * g_lpdwThreadsIdArray = NULL;


VOID WINAPI EtwEventCallback(PEVENT_RECORD EventRecord) {
	EVENT_HEADER &hdr = EventRecord->EventHeader;
	LPTSTR lpOldThrState = NULL;

	UCHAR cpuId = EventRecord->BufferContext.ProcessorNumber;
	ULONG dwOldThrId = 0, dwNewThrId = 0;
	INT64 CycleTime = hdr.TimeStamp.QuadPart;

	if (EventRecord->EventHeader.EventDescriptor.Opcode != 36 || EventRecord->EventHeader.EventDescriptor.Version != 3) {
		PTRACE_EVENT_INFO pEvtInfo = NULL;
		GetEventInformation(EventRecord, pEvtInfo);
		if (pEvtInfo) delete pEvtInfo;
		return;
	}

	if (EventRecord->UserData) {
		CSwitch * pThrSwitch = (CSwitch*)EventRecord->UserData;
		_ASSERT(EventRecord->UserDataLength == sizeof(CSwitch));
		dwNewThrId = pThrSwitch->NewThreadId;
		dwOldThrId = pThrSwitch->OldThreadId;
		if (pThrSwitch->OldThreadState == 0) lpOldThrState = L"Initialized";
		else if (pThrSwitch->OldThreadState == 1) lpOldThrState = L"Ready";
		else if (pThrSwitch->OldThreadState == 2) lpOldThrState = L"Running";
		else if (pThrSwitch->OldThreadState == 3) lpOldThrState = L"Standby";
		else if (pThrSwitch->OldThreadState == 4) lpOldThrState = L"Terminated";
		else if (pThrSwitch->OldThreadState == 5) lpOldThrState = L"Waiting";
		else if (pThrSwitch->OldThreadState == 6) lpOldThrState = L"Transition";
		else if (pThrSwitch->OldThreadState == 7) lpOldThrState = L"DeferredReady";
		for (int i = 0; i < g_iNumOfThreads; i++) {
			if (g_lpdwThreadsIdArray[i] == dwNewThrId || g_lpdwThreadsIdArray[i] == dwOldThrId) {
				wprintf(L"[EtwContextSwitch] Processor: %i, New thread ID: %i, Old thread ID: %i (state: %s).\r\n", cpuId, dwNewThrId, dwOldThrId, lpOldThrState);
				DbgBreak();
			}
		}
	}
}


DWORD WINAPI TraceThread(LPVOID lpParam) {
	TRACEHANDLE hConsumer = (TRACEHANDLE)lpParam;
	DWORD dwNumOfThreads = 0;
	BOOL bRetVal = FALSE;
	DWORD dwCurProcId = GetCurrentProcessId();
	if (!hConsumer) return -1;

	// Enumerate all the threads of this process and add it to the global list
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te = { 0 };
		int count = 0;
		te.dwSize = sizeof(te);
		bRetVal = Thread32First(h, &te);

		while (bRetVal) {
			if (te.th32OwnerProcessID == dwCurProcId)
				dwNumOfThreads++;
			te.dwSize = sizeof(te);
			bRetVal = Thread32Next(h, &te);
		}

		// Allocate enough memory
		g_lpdwThreadsIdArray = new DWORD[dwNumOfThreads];
		g_iNumOfThreads = dwNumOfThreads;

		bRetVal = Thread32First(h, &te);
		while (bRetVal) {
			if (te.th32OwnerProcessID == dwCurProcId)
				g_lpdwThreadsIdArray[count++] = te.th32ThreadID;
			te.dwSize = sizeof(te);
			bRetVal = Thread32Next(h, &te);
		}
		CloseHandle(h);
	}
	ProcessTrace(&hConsumer, 1, NULL, NULL);
	return 0;
}


bool StartEtwTrace() {
	PEVENT_TRACE_PROPERTIES pEtwProp = NULL;			// The main ETW structure
	EVENT_TRACE_LOGFILE etwLogFile = { 0 };				// The structure used to grab log events
	LPTSTR providerName = NULL;							// The ETW provider name
	DWORD dwCbProvName = 0,								// The ETW provider name size in BYTES
		dwEtwPropSize = 0;								// The ETW Trace Proprieties data structure size in bytes
	TRACEHANDLE hTrace = NULL;							// The ETW handle
	TRACEHANDLE hConsumerTrace = NULL;					// The handle to the actual ETW consumer
	BOOL bRetVal = FALSE;								// The returned value from Win32
	DWORD dwLastErr = 0;								// Last Win32 error

	providerName = KERNEL_LOGGER_NAME;
	dwCbProvName = (DWORD)(wcslen(providerName) + 1) * sizeof(TCHAR);

	// Allocate the memory for the ETW data structure
	dwEtwPropSize = sizeof(EVENT_TRACE_PROPERTIES) + dwCbProvName;
	pEtwProp = (PEVENT_TRACE_PROPERTIES)new BYTE[dwEtwPropSize];
	RtlZeroMemory(pEtwProp, dwEtwPropSize);

	pEtwProp->Wnode.ClientContext = 1;								// Query performance counter (QPC)
	pEtwProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;					// The only flag currently available
	pEtwProp->Wnode.Guid = SystemTraceControlGuid;
	pEtwProp->Wnode.BufferSize = dwEtwPropSize;
	// Copy the name at the end of the structure
	RtlCopyMemory(((LPBYTE)pEtwProp + sizeof(EVENT_TRACE_PROPERTIES)), providerName, dwCbProvName);

	// Stop any previous kernel trace consumer (if no previous session, return value is ERROR_WMI_INSTANCE_NOT_FOUND)
	bRetVal = ControlTrace(NULL, providerName, pEtwProp, EVENT_TRACE_CONTROL_STOP);
	if (bRetVal != ERROR_WMI_INSTANCE_NOT_FOUND) {
		DWORD dwOffset = FIELD_OFFSET(EVENT_TRACE_PROPERTIES, BufferSize);
		RtlZeroMemory((LPBYTE)pEtwProp + dwOffset, dwEtwPropSize - dwOffset);
	}
	pEtwProp->EnableFlags = EVENT_TRACE_FLAG_CSWITCH;				// Trace the thread context switches
	pEtwProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;				// Realtime trace mode ON
	pEtwProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);	// The offset of the provider name or GUID

	// Start trace consumer
	// This requires Administrative user or 'Performance Log Users' group
	wprintf(L"Initializing the ETW Consumer... ");
	bRetVal = StartTrace(&hTrace, providerName, pEtwProp);

	if (bRetVal == ERROR_SUCCESS) {
		RtlZeroMemory(&etwLogFile, sizeof(EVENT_TRACE_LOGFILE));
		etwLogFile.LoggerName = providerName;
		etwLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
		etwLogFile.EventRecordCallback = EtwEventCallback;

		hConsumerTrace = OpenTrace(&etwLogFile);
		dwLastErr = GetLastError();
		bRetVal = (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE) ? ERROR_SUCCESS : dwLastErr;
	}

	if (bRetVal == ERROR_SUCCESS) {
		DWORD dwThrId = 0;
		HANDLE hThread = NULL;
		cl_wprintf(GREEN, L"Success.\r\n"); 

		// Spawn some test threads:
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestThread1, (LPVOID)NULL, 0, &dwThrId);
		CloseHandle(hThread);

		// Spawn the blocking trace thread
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TraceThread, (LPVOID)hConsumerTrace, 0, &dwThrId);
		CloseHandle(hThread);

		// Now wait the user to end the app
		wprintf(L"Press ENTER key to stop the trace and exit...");
		rewind(stdin);
		getwchar();
	}
	else 
		cl_wprintf(RED, L"Error %i.\r\n", (LPVOID)bRetVal);


	// Stop our Kernel Logger consumer
	if (hConsumerTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE)
		bRetVal = ControlTrace(hConsumerTrace, NULL, pEtwProp, EVENT_TRACE_CONTROL_STOP);
	if (pEtwProp) delete pEtwProp;
	return (bRetVal == ERROR_SUCCESS);
}

// A test thread 
DWORD WINAPI TestThread1(LPVOID lpParam) {
	LARGE_INTEGER curTime = { 0 };
	while (TRUE) {
		DWORD dwKey = 0;
		QueryPerformanceCounter(&curTime);
		dwKey = _rotr(curTime.LowPart, curTime.HighPart) * 56 / 11;
		Sleep(1);
	}
}



#pragma ETW Parsing 
#include <combaseapi.h>
#include <in6addr.h>
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);

// Get the metadata for the event.
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo)
{
	DWORD status = ERROR_SUCCESS;
	LPWSTR pwsEventGuid = NULL;
	DWORD BufferSize = 0;
	DWORD dwPointerSize = 0;
	PBYTE pUserData = NULL;						// The Event data
	PBYTE pEndOfUserData = NULL;				// The end of the event data

	// Retrieve the required buffer size for the event metadata.
	status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

	if (ERROR_INSUFFICIENT_BUFFER == status) {
		pInfo = (TRACE_EVENT_INFO*)new BYTE[BufferSize];
		if (pInfo == NULL) {
			wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
			status = ERROR_OUTOFMEMORY;
		}

		// Retrieve the event metadata.
		status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
	}

	if (pInfo && pInfo->DecodingSource == DecodingSourceWbem)  // MOF class
	{
		HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

		if (FAILED(hr)) {
			wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
			status = hr;
		}

		wprintf(L"\nEvent GUID: %s\n", pwsEventGuid);
		CoTaskMemFree(pwsEventGuid);
		pwsEventGuid = NULL;
		wprintf(L"Event ID: %d\n", pEvent->EventHeader.EventDescriptor.Id);
	}
	else if (pInfo->DecodingSource == DecodingSourceXMLFile)	// Instrumentation manifest
		wprintf(L"Event ID: %d\n", pInfo->EventDescriptor.Id);

	wprintf(L"Event version: %d\n", pEvent->EventHeader.EventDescriptor.Version);
	wprintf(L"Event type: %d\n", pEvent->EventHeader.EventDescriptor.Opcode);

	if (ERROR_SUCCESS != status) {
		//wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
		if (pInfo) delete pInfo;
		return status;
	}


	if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
		dwPointerSize = 4;
	else
		dwPointerSize = 8;

	pUserData = (PBYTE)pEvent->UserData;
	pEndOfUserData = (PBYTE)pEvent->UserData + pEvent->UserDataLength;

	// Print the event data for all the top-level properties. Metadata for all the 
	// top-level properties come before structure member properties in the 
	// property information array.
	for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
	{
		pUserData = PrintProperties(pEvent, pInfo, dwPointerSize, i, pUserData, pEndOfUserData);
		if (pUserData == NULL)
			wprintf(L"Printing top level properties failed.\n");
	}

	return status;
}

// Print the property.
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData)
{
	TDHSTATUS status = ERROR_SUCCESS;
	USHORT PropertyLength = 0;
	DWORD FormattedDataSize = 0;
	USHORT UserDataConsumed = 0;
	USHORT UserDataLength = 0;
	LPWSTR pFormattedData = NULL;
	DWORD LastMember = 0;  // Last member of a structure
	USHORT ArraySize = 0;
	PEVENT_MAP_INFO pMapInfo = NULL;


	// Get the length of the property.
	status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength);
	if (ERROR_SUCCESS != status)
	{
		wprintf(L"GetPropertyLength failed.\n");
		pUserData = NULL;
		goto cleanup;
	}

	// Get the size of the array if the property is an array.
	status = GetArraySize(pEvent, pInfo, i, &ArraySize);

	for (USHORT k = 0; k < ArraySize; k++)
	{
		// If the property is a structure, print the members of the structure.
		if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
		{
			LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
				pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

			for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
			{
				pUserData = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
				if (NULL == pUserData)
				{
					wprintf(L"Printing the members of the structure failed.\n");
					pUserData = NULL;
					goto cleanup;
				}
			}
		}
		else
		{
			// Get the name/value mapping if the property specifies a value map.
			status = GetMapInfo(pEvent,
				(PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
				pInfo->DecodingSource,
				pMapInfo);

			if (ERROR_SUCCESS != status)
			{
				wprintf(L"GetMapInfo failed\n");
				pUserData = NULL;
				goto cleanup;
			}

			// Get the size of the buffer required for the formatted data.
			status = TdhFormatProperty(
				pInfo,
				pMapInfo,
				PointerSize,
				pInfo->EventPropertyInfoArray[i].nonStructType.InType,
				pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
				PropertyLength,
				(USHORT)(pEndOfUserData - pUserData),
				pUserData,
				&FormattedDataSize,
				pFormattedData,
				&UserDataConsumed);

			if (ERROR_INSUFFICIENT_BUFFER == status)
			{
				if (pFormattedData)
				{
					free(pFormattedData);
					pFormattedData = NULL;
				}

				pFormattedData = (LPWSTR)malloc(FormattedDataSize);
				if (pFormattedData == NULL)
				{
					wprintf(L"Failed to allocate memory for formatted data (size=%lu).\n", FormattedDataSize);
					status = ERROR_OUTOFMEMORY;
					pUserData = NULL;
					goto cleanup;
				}

				// Retrieve the formatted data.

				status = TdhFormatProperty(
					pInfo,
					pMapInfo,
					PointerSize,
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
					PropertyLength,
					(USHORT)(pEndOfUserData - pUserData),
					pUserData,
					&FormattedDataSize,
					pFormattedData,
					&UserDataConsumed);
			}

			if (ERROR_SUCCESS == status)
			{
				wprintf(L"%s: %s\n",
					(PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset),
					pFormattedData);

				pUserData += UserDataConsumed;
			}
			else
			{
				wprintf(L"TdhFormatProperty failed with %lu.\n", status);
				pUserData = NULL;
				goto cleanup;
			}
		}
	}

cleanup:

	if (pFormattedData)
	{
		free(pFormattedData);
		pFormattedData = NULL;
	}

	if (pMapInfo)
	{
		free(pMapInfo);
		pMapInfo = NULL;
	}

	return pUserData;
}

// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
		*ArraySize = (USHORT)Count;
	}
	else
	{
		*ArraySize = pInfo->EventPropertyInfoArray[i].count;
	}

	return status;
}

// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
	DWORD status = ERROR_SUCCESS;
	DWORD MapSize = 0;

	// Retrieve the required buffer size for the map info.
	status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

	if (ERROR_INSUFFICIENT_BUFFER == status)
	{
		pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
		if (pMapInfo == NULL)
		{
			wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		// Retrieve the map info.
		status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
	}

	if (ERROR_SUCCESS == status)
	{
		if (DecodingSourceXMLFile == DecodingSource)
		{
			RemoveTrailingSpace(pMapInfo);
		}
	}
	else
	{
		if (ERROR_NOT_FOUND == status)
		{
			status = ERROR_SUCCESS; // This case is okay.
		}
		else
		{
			wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
		}
	}

cleanup:

	return status;
}

// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
	DWORD ByteLength = 0;

	for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
	{
		ByteLength = (DWORD)(wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
		*((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
	}
}

// Get the length of the property data. For MOF-based events, the size is inferred from the data type
// of the property. For manifest-based events, the property can specify the size of the property value
// using the length attribute. The length attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size. If the property does not include the 
// length attribute, the size is inferred from the data type. The length will be zero for variable
// length, null-terminated strings and structures.
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	// If the property is a binary blob and is defined in a manifest, the property can 
	// specify the blob's size or it can point to another property that defines the 
	// blob's size. The PropertyParamLength flag tells you where the blob's size is defined.
	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
	{
		DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
		*PropertyLength = (USHORT)Length;
	}
	else
	{
		if (pInfo->EventPropertyInfoArray[i].length > 0)
		{
			*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
		}
		else
		{
			// If the property is a binary blob and is defined in a MOF class, the extension
			// qualifier is used to determine the size of the blob. However, if the extension 
			// is IPAddrV6, you must set the PropertyLength variable yourself because the 
			// EVENT_PROPERTY_INFO.length field will be zero.
			if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
				TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
			{
				*PropertyLength = (USHORT)sizeof(IN6_ADDR);
			}
			else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				(pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
			{
				*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
			}
			else
			{
				wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

				status = ERROR_EVT_INVALID_EVENT_DATA;
				goto cleanup;
			}
		}
	}

cleanup:

	return status;
}
#pragma endregion