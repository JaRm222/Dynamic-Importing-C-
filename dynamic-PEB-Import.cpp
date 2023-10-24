#include <iostream>
#include <Windows.h>
#include <winternl.h>


bool CompareUnicodeStringToValue(const UNICODE_STRING& unicodeString, const char* predefinedValue) {
	// Calculate the required buffer size for the multi-byte string
	int requiredSize = WideCharToMultiByte(CP_UTF8, 0, unicodeString.Buffer, unicodeString.Length / sizeof(WCHAR), NULL, 0, NULL, NULL);

	// Allocate a buffer to hold the multi-byte string
	char* multiByteString = new char[requiredSize + 1];

	// Convert the Unicode string to multi-byte
	WideCharToMultiByte(CP_UTF8, 0, unicodeString.Buffer, unicodeString.Length / sizeof(WCHAR), multiByteString, requiredSize, NULL, NULL);

	// Null-terminate the multi-byte string
	multiByteString[requiredSize] = '\0';

	// Compare the multi-byte string with the predefined value
	bool result = (strcmp(multiByteString, predefinedValue) == 0);

	// Clean up the dynamically allocated memory
	delete[] multiByteString;

	return result;
}

unsigned __int64 getModuleBasePEB(const char* moduleName)
{
	// Thread Environment Block (TEB)
#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	// Process Environment Block (PEB)
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;

	//Get pointer to loader
	PPEB_LDR_DATA pLdr = pebPtr->Ldr;
	PLIST_ENTRY pEntry = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY curr = pEntry->Flink;

	do {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (CompareUnicodeStringToValue(entry->FullDllName, moduleName)) {
			return (unsigned __int64)entry->DllBase;
		}
		curr = curr->Flink;
	} while (curr != pEntry);

	return 0;
}

unsigned __int64 getModuleExport(unsigned __int64 modBase, const char* exportName)
{
	PIMAGE_DOS_HEADER dosHeader =	nullptr;
	PIMAGE_NT_HEADERS ntHeader	=	nullptr;

	dosHeader	= (PIMAGE_DOS_HEADER)modBase;
	ntHeader	= (PIMAGE_NT_HEADERS)(modBase + dosHeader->e_lfanew);

	// Now we need to get the export table
	// First we get the Relative Virtual Address
	DWORD						exportRVA		=	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY		exportTable		=	(PIMAGE_EXPORT_DIRECTORY)(modBase + exportRVA);

	/* 
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image <--- It points to an array of words. So we can just interpret it as a WORD*
	*/

	DWORD* functionTable	= (DWORD*)(modBase + exportTable->AddressOfFunctions);
	DWORD*	nameTable		= (DWORD*)(modBase + exportTable->AddressOfNames);
	WORD*	ordinalTable	= (WORD*)(modBase + exportTable->AddressOfNameOrdinals);


	for (int i = 0; i < exportTable->NumberOfNames; i++) 
	{
		char*			  funcName	= (char*)(modBase + nameTable[i]);
		unsigned __int64  func_ptr = modBase + functionTable[ordinalTable[i]];

		if (!_strcmpi(funcName, exportName)) 
		{
			return func_ptr;
		}
		
	}
	return 0;

}

using createProcProto = HANDLE(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

int main()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	unsigned __int64 modBase = getModuleBasePEB("C:\\Windows\\System32\\KERNEL32.DLL");
	if (modBase == 0) { return 0; }

	std::cout << "Kernel32.dll @ " << modBase << "\n";
	unsigned __int64 functionAddy = getModuleExport(modBase, "CreateProcessA");
	std::cout << "OpenProcess @ " << functionAddy << "\n";

	createProcProto createProc = (createProcProto)functionAddy;
	createProc(
		"C:\\Windows\\System32\\calc.exe",  // Path to calc.exe
		NULL,                               // Command line (none needed for Calculator)
		NULL,                               // Process handle not inheritable
		NULL,                               // Thread handle not inheritable
		FALSE,                              // Handle inheritance option
		0,                                  // Creation flags
		NULL,                               // Use parent's environment block
		NULL,                               // Use parent's starting directory
		&si,                                // Pointer to STARTUPINFO
		&pi                                 // Pointer to PROCESS_INFORMATION
	);
}
