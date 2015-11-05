
RemoteThreader (64 bit)
==========================

Injects a dll from command line to the given process memory. Tested only on 64 bit process and 64 bit dll.

Download the file from x64/Release/RemoteThreader.exe

You probably first need the [VS 2015 runtimes vc_redist.x64.exe and/or vc_redist.x86.exe](https://www.microsoft.com/en-us/download/details.aspx?id=48145), if they are not installed already. I've built the executable using VS 2015, and Microsoft is not providing those runtimes (who knows why) with Windows 10 yet.

Usage
---------

	RemoteThreader [processName] [DLLpath] ([functionName]) ([functionArgument])
	  Function argument is given to function as wchar_t*
	  If you omit function name and function argument, program tries to free the dll.
  

Notes
---------

For debugging and testing this program you need a DLL and process, in the project settings I have used: 
https://github.com/HotKeyIt/ahkdll-v1-release (x64w/AutoHotkey.dll) placed in the solution directory and notepad.exe as process to inject to.

MIT Licensed, see LICENSE
Jari Pennanen, 2015