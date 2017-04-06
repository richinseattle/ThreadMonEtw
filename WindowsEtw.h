#ifndef WINDOWSETW_H
#define WINDOWSETW_H


#define INITGUID 1
#include <Evntcons.h>
#include <Tdh.h>

struct CSwitch 
{
	UINT32 NewThreadId;						// + 0x00
	UINT32 OldThreadId;						// + 0x04
	INT8 NewThreadPriority;					// + 0x08
	INT8 OldThreadPriority;					// + 0x09
	UINT8 PreviousCState;					// + 0x0A
	INT8 SpareByte;							// + 0x0B
	INT8 OldThreadWaitReason;				// + 0x0C
	INT8 OldThreadWaitMode;					// + 0x0D
	INT8 OldThreadState;					// + 0x0E
	INT8 OldThreadWaitIdealProcessor;		// + 0x0F
	UINT32 NewThreadWaitTime;				// + 0x10
	UINT32 Reserved;						// + 0x14
};
C_ASSERT(sizeof(CSwitch) == 0x18);

// Try to start the ETW tracing (consumer)
bool StartEtwTrace();

// The ETW event record callback routine
VOID WINAPI EtwEventCallback(PEVENT_RECORD EventRecord);

DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);


// The tracing thread 
DWORD WINAPI TraceThread(LPVOID lpParam);

// The test thread 1
DWORD WINAPI TestThread1(LPVOID lpParam);


#endif // WINDOWSETW_H