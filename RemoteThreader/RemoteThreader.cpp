// RemoteThreader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

/*
void PrintSnapshotProcess(HANDLE hProcess, DWORD pid) {
	HANDLE mSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (mSnapshot == INVALID_HANDLE_VALUE) {
		std::wcout << "Cant get snapshot of process." << std::endl;
	}

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(mSnapshot, &moduleEntry);
	std::wcout << "Module: " << moduleEntry.szExePath << std::endl;
	std::wcout << "Address: " << moduleEntry.modBaseAddr << std::endl;

	while (Module32Next(mSnapshot, &moduleEntry)) {
		std::wcout << "Module: " << moduleEntry.szExePath << std::endl;
		std::wcout << "Address: " << moduleEntry.modBaseAddr << std::endl;
	}
}
*/

void FreeMemoryInRemote(HANDLE hProcess, LPVOID address, SIZE_T size) {
	if (address == 0) {
		return;
	}
	VirtualFreeEx(hProcess, address, size, MEM_RELEASE);
	wcout << "Freed ";
	printf("%zu", size);
	wcout << " bytes in address: 0x" << hex << address << std::endl;
}

LPVOID ReserveMemoryInRemote(HANDLE hProcess, LPVOID buffer, SIZE_T size) {
	LPVOID bufferBegin = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!bufferBegin) {
		wcerr << "Unable to allocate space from process." << std::endl;
		return 0;
	}
	std::wcout << "Allocated ";
	printf("%zu", size);
	wcout << " bytes in address: " << hex << bufferBegin << std::endl;

	SIZE_T bytesWritten;
	WriteProcessMemory(hProcess, bufferBegin, buffer, size, &bytesWritten);
	if (!bytesWritten || bytesWritten != size) {
		FreeMemoryInRemote(hProcess, bufferBegin, size);
		wcerr << "Can't write everything to process, only " << bytesWritten << " bytes were written at 0x" << hex << bufferBegin << std::endl;
		return 0;
	}

	wcout << "Wrote ";
	printf("%zu", bytesWritten);
	wcout << " bytes to address: 0x" << hex << bufferBegin << std::endl;
	return bufferBegin;
}

LPVOID ReserveMemoryInRemote(HANDLE hProcess, wstring str) {
	return ReserveMemoryInRemote(hProcess, (LPVOID) str.c_str(), str.size() * sizeof(wchar_t));
}


void FreeMemoryInRemote(HANDLE hProcess, LPVOID address, wstring str) {
	return FreeMemoryInRemote(hProcess, address, str.size() * sizeof(wchar_t));
}

bool InjectToRemoteThread(HANDLE hProcess, std::wstring dllPath) {
	HMODULE kernel32 = LoadLibrary(L"kernel32.dll");
	FARPROC addrLoadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
	//FARPROC addrFreeLibrary = GetProcAddress(kernel32, "FreeLibrary");
	if (!addrLoadLibrary) {
		std::wcout << "LoadLibraryW address not found";
		return false;
	}
	std::wcout << "LoadLibraryW address: 0x" << hex << ((LPTHREAD_START_ROUTINE) addrLoadLibrary) << std::endl;

	LPVOID dllPathInMemory = ReserveMemoryInRemote(hProcess, dllPath);
	if (!dllPathInMemory) {
		std::wcout << "Unable to reserve memory for AHK dll path." << std::endl;
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)addrLoadLibrary, dllPathInMemory, 0, 0);
	if (!hThread) {
		FreeMemoryInRemote(hProcess, dllPathInMemory, dllPath);
		std::wcout << "Unable to create remote thread for AHK dll" << std::endl;
		return false;
	}
	std::wcout << "Injected a dll with thread: " << hThread << std::endl;

	WaitForSingleObject(hThread, 0xFFFFFFFF);
	DWORD exitCode;
	// GetExitCodeThread(hThread, &exitCode);
	// std::wcout << "Exit code for AHK thread: " << exitCode << std::endl;
	CloseHandle(hThread);
	FreeMemoryInRemote(hProcess, dllPathInMemory, dllPath);
	return true;
}

bool RunFunctionInRemoteThread(HANDLE hProcess, DWORD_PTR dllAddress, wstring dllPath, string functionName, wstring functionArgument) {
	// Write function argument to memory
	LPVOID functionArgumentAddress = NULL;
	if (!functionArgument.empty()) {
		functionArgumentAddress = ReserveMemoryInRemote(hProcess, functionArgument);
		if (functionArgumentAddress == NULL) {
			cerr << "Can't write function argument in the process memory." << endl;
			return false;
		}
		cout << "Wrote function argument at the address: 0x" << hex << functionArgumentAddress << endl;
	}

	// Calculate position of function
	DWORD_PTR localDll = (DWORD_PTR)LoadLibrary(dllPath.c_str());
	if (!localDll) {
		FreeMemoryInRemote(hProcess, functionArgumentAddress, functionArgument);
		cerr << "Can't load injected dll in this process." << endl;
		return false;
	}
	// Get function address in this procees
	DWORD_PTR funcAddress = (DWORD_PTR)GetProcAddress((HMODULE)localDll, functionName.c_str());
	if (funcAddress == 0) {
		FreeMemoryInRemote(hProcess, functionArgumentAddress, functionArgument);
		cout << "Can't find function named: " << functionName << endl;
		return false;
	}

	DWORD_PTR remoteFuncAddress = dllAddress - localDll + funcAddress;
	cout << "Execute function at remote address: 0x" << hex << remoteFuncAddress << endl;
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)remoteFuncAddress, functionArgumentAddress, 0, 0);
	WaitForSingleObject(hThread, 0xFFFFFFFF);
	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);
	cout << "Done with exit code: 0x" << hex << exitCode << endl;
	FreeMemoryInRemote(hProcess, functionArgumentAddress, functionArgument);
	return true;
}

void FreeFromRemoteThread(HANDLE hProcess, HANDLE module) {
	HMODULE kernel32 = LoadLibrary(L"kernel32.dll");
	FARPROC addrFreeLibrary = GetProcAddress(kernel32, "FreeLibrary");
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)addrFreeLibrary, module, 0, 0);
	WaitForSingleObject(hThread, 0xFFFFFFFF);
	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);
}

DWORD_PTR FindModuleAddress(DWORD pid, std::wstring moduleName) {
	HANDLE mSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (mSnapshot == INVALID_HANDLE_VALUE) {
		std::wcerr << "Can't get snapshot of process." << std::endl;
		return 0;
	}
	
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(mSnapshot, &moduleEntry);
	//std::wcout << "Module: " << moduleEntry.szExePath << std::endl;
	//std::wcout << "Address: " << moduleEntry.modBaseAddr << std::endl;

	if (_wcsicmp(moduleEntry.szExePath, moduleName.c_str()) == 0) {
		return (DWORD_PTR) moduleEntry.modBaseAddr;
	}

	while (Module32Next(mSnapshot, &moduleEntry)) {
		//std::wcout << "Module: " << moduleEntry.szExePath << std::endl;
		//std::wcout << "Address: " << moduleEntry.modBaseAddr << std::endl;

		if (_wcsicmp(moduleEntry.szExePath, moduleName.c_str()) == 0) {
			return (DWORD_PTR)moduleEntry.modBaseAddr;
		}
	}

	return 0;
}

PROCESSENTRY32* FindProcessEntry(const wchar_t* processName) {
	PROCESSENTRY32 *entry = new PROCESSENTRY32();
	entry->dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, entry) == TRUE) {
		while (Process32Next(snapshot, entry) == TRUE) {
			if (_wcsicmp(entry->szExeFile, processName) == 0) {
				CloseHandle(snapshot);
				return entry;
			}
		}
	}

	CloseHandle(snapshot);
	return NULL;
}


int wmain(int argc, wchar_t** argv) {
	if (argc < 3) {
		wcout << L"RemoteThreader [processName] [DLLpath] ([functionName]) ([functionArgument])" << endl;
		wcout << L"  Version: 0.1" << endl;
		wcout << L"  Function argument is given to function as wchar_t*" << endl;
		wcout << L"  If you omit function name and function argument, program tries to free the dll." << endl;
		wcout << endl;
		wcout << L"  MIT License, Copyright (c) Jari Pennanen, 2015" << endl;
		wcout << L"  Source code at https://github.com/Ciantic/RemoteThreader" << endl;
		return 1;
	}

	// Parse arguments
	vector<wstring> args;
	args.assign(argv + 1, argv + argc);
	wstring processName = args[0];
	wstring dllPath = wstring(_wfullpath(0, args[1].c_str(), 3024 * sizeof(wchar_t)));
	wstring functionName = args.size() > 2 ? args[2] : L"";
	wstring functionArgument = args.size() > 3 ? args[3] : L"";
	string functionNameAnsi(functionName.begin(), functionName.end());
	
	wcout << "Process name: " << processName << endl;
	wcout << "DLL path: " << dllPath << endl;
	cout << "Function name: " << functionNameAnsi << endl;
	wcout << "Function argument: " << functionArgument << endl;

	// Find process entry (PID, etc.)
	PROCESSENTRY32 *processEntry = FindProcessEntry(processName.c_str());
	if (processEntry == NULL) {
		cerr << "Can't find process entry." << endl;
		return 1;
	}
	cout << "Operating on process with PID: " << processEntry->th32ProcessID << endl;
	
	// Open the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry->th32ProcessID);
	if (!hProcess) {
		cerr << "Can't find process." << endl;
		return 1;
	}
	cout << "Process opened with handle: 0x" << hex << hProcess << endl;

	// Find if the dll is already injected
	DWORD_PTR dllAddress = FindModuleAddress(processEntry->th32ProcessID, dllPath);

	// Command line arguments functionName and functionArgument is not given
	if (functionName.empty()) {
		if (dllAddress != 0) {
			FreeFromRemoteThread(hProcess, (HANDLE)dllAddress);
			cout << "Freed the DLL found in address: 0x" << hex << dllAddress << endl;
		} else {
			cout << "DLL was not found in the process, nothing to be freed." << endl;
		}

	// All command line arguments are assumed to be given
	} else {
		if (dllAddress == 0) {
			// Inject the dll
			if (!InjectToRemoteThread(hProcess, dllPath)) {
				wcerr << "Unable to inject to process" << endl;
				CloseHandle(hProcess);
				return 1;
			}
			dllAddress = FindModuleAddress(processEntry->th32ProcessID, dllPath);
			if (dllAddress == 0) {
				wcerr << "Injection tried, but DLL not found: " << dllPath << endl;
				CloseHandle(hProcess);
				return 1;
			}
		}
		cout << "Injected DLL found in address: 0x" << hex << dllAddress << endl;
		RunFunctionInRemoteThread(hProcess, dllAddress, dllPath, functionNameAnsi, functionArgument);
	}
	CloseHandle(hProcess);
    return 0;
}

