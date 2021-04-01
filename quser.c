#include <windows.h>
#include <wtsapi32.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI WTSAPI32$WTSOpenServerA (LPSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI WTSAPI32$WTSEnumerateSessionsA (HANDLE, DWORD, DWORD, PWTS_SESSION_INFOA *, DWORD *);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI WTSAPI32$WTSQuerySessionInformationA (HANDLE, DWORD, WTS_INFO_CLASS, LPSTR *, DWORD *);
DECLSPEC_IMPORT WINBASEAPI void WINAPI WTSAPI32$WTSFreeMemory (PVOID);
DECLSPEC_IMPORT WINBASEAPI void WINAPI WTSAPI32$WTSCloseServer (HANDLE);

void go(char * args, int alen)
{	
	datap parser;
	PWTS_SESSION_INFOA pwsi;
	DWORD dwCount = 0;
	DWORD bytesReturned = 0;
	BeaconDataParse(&parser, args, alen);
	char *targetHost = BeaconDataExtract(&parser, NULL);
	char *addrFamily = "";
	char *stateInfo = "";
	HANDLE hTarget = NULL;
	LPTSTR userName, userDomain, clientName, clientAddress;
	PWTS_CLIENT_ADDRESS clientAddressStruct = NULL;
	BOOL successGetSession = 0;
	hTarget = WTSAPI32$WTSOpenServerA(targetHost);
	successGetSession = WTSAPI32$WTSEnumerateSessionsA(hTarget, 0, 1, &pwsi, &dwCount);
	if(!successGetSession){
		if(KERNEL32$GetLastError()==5)
			BeaconPrintf(CALLBACK_OUTPUT, "Access denied: Could not connect to %s.", targetHost);
		else
			BeaconPrintf(CALLBACK_OUTPUT, "ERROR %d: Could not connect to %s.", KERNEL32$GetLastError(), targetHost);
	} else {
		BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15s%-15s%-18s%s", "UserDomain", "UserName", "SessionName", "SessionID" , "State", "SourceAddress", "SourceClientName");
		for (unsigned int i = 0; i < dwCount; i++)
		{
			WTS_SESSION_INFO si = pwsi[i];
			if(si.SessionId > 2048 || si.SessionId < 0)
				continue;
			BOOL getResult;
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSUserName, &userName, &bytesReturned);
			if(!getResult){
				userName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSDomainName, &userDomain, &bytesReturned);
			if(!getResult){
				userDomain = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientName, &clientName, &bytesReturned);
			if(!getResult){
				clientName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientAddress, &clientAddress, &bytesReturned);
			if(!getResult){
				clientAddress = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			clientAddressStruct = (PWTS_CLIENT_ADDRESS)clientAddress;
			if(clientAddressStruct->AddressFamily == 0)
				addrFamily = "Unspecified";
			else if(clientAddressStruct->AddressFamily == 2)
				addrFamily = "InterNetwork";
			else if(clientAddressStruct->AddressFamily == 17)
				addrFamily = "NetBios";
			else 
				addrFamily = "Unknown";
			if(strlen(userName)){
				if(si.State == WTSActive)
					stateInfo = "Active";
				else if(si.State == WTSConnected)
					stateInfo = "Connected";
				else if(si.State == WTSDisconnected)
					stateInfo = "Disconnected";
				else if(si.State == WTSIdle)
					stateInfo = "Idle";
				else 
					stateInfo = "Unknown";
				if(addrFamily == "Unspecified")
					BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%-18s%s", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, "-", "-");
				else
					BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%u.%u.%u.%-6u%s", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, clientAddressStruct->Address[2], clientAddressStruct->Address[3], clientAddressStruct->Address[4], clientAddressStruct->Address[5], clientName);
			}
		}
	}
	WTSAPI32$WTSFreeMemory(pwsi);
	WTSAPI32$WTSCloseServer(hTarget);
};
