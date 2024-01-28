.code

extern wNtAllocateVirtualMemory : DWORD
extern sysAddrNtAllocateVirtualMemory : QWORD
extern wNtWriteVirtualMemory : DWORD
extern sysAddrNtWriteVirtualMemory : QWORD
extern wNtCreateThreadEx : DWORD
extern sysAddrNtCreateThreadEx : QWORD
extern wNtWaitForSingleObject : DWORD
extern sysAddrNtWaitForSingleObject : QWORD

public CustomNtAllocateVirtualMemory
public CustomNtWriteVirtualMemory
public CustomNtCreateThreadEx
public CustomNtWaitForSingleObject

CustomNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemory
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]
CustomNtAllocateVirtualMemory ENDP

CustomNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
CustomNtWriteVirtualMemory ENDP

CustomNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
CustomNtCreateThreadEx ENDP

CustomNtWaitForSingleObject PROC
	mov r10, rcx
	mov eax, wNtWaitForSingleObject
	jmp QWORD PTR [sysAddrNtWaitForSingleObject]
CustomNtWaitForSingleObject ENDP

END