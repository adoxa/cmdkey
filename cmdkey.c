/*
  cmdkey.c - Enhanced command line editing for CMD.EXE.

  Jason Hood, 24 October to 21 November, 2005 and 20 to 23 December, 2006.

  Injection code derived from Console Manager by Sergey Oblomov (hoopoepg).
  Additional information from "Process-wide API spying - an ultimate hack" By
  Anton Bassov's article in "The Code Project" (use of OpenThread).

  v1.02, 23 July, 2010:
  + add -I/-U to use HKLM.

  v2.00, 22 July to 8 August, 2011:
  * compile cleanly with GCC 4;
  * slight improvements in finding parent process;
  * install as a batch file (cmdkey.cmd) to improve load time for "cmd /c";
  * -e applies to any search, not just blank;
  - fixed updating the config file;
  + option to specify file for a persistent history;
  * use specific options for each prompt colour;
  + added colour for the prompt's base directory;
  + added -_ to control whether underscore is part of a word;
  + added -km to choose the selection colour;
  * test the config file is readable here, not in edit;
  + added --version;
  - fixed the status (using wrong value of enabled; future-proof);
  * removed NT version
  - fixed initial install.

  v2.10, 14 & 15 June, 2012:
  * modified injection (use VirtualAllocEx method, not stack);
  + 64-bit version;
  - search for the local export (improved future-proofing);
  - install/uninstall will replace/remove a string containing "cmdkey".

  21 May, 2013:
  - fixed status in 64-bit version.

  27 May, 2013:
  * use CreateRemoteThread injection method (and LoadLibraryW);
  - prevent 32/64 mismatch.
*/

#define PDATE "1 June, 2013"

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cmdkey.h"
#include "version.h"

#ifndef offsetof
# define offsetof(type, member) (size_t)(&(((type*)0)->member))
#endif

#ifdef __MINGW32__
int _CRT_glob = 0;
#endif


#define CMDKEY	"Software\\Microsoft\\Command Processor"
#define AUTORUN "AutoRun"


void status( void );
void help( void );

BOOL  find_proc_id( HANDLE snap, DWORD id, LPPROCESSENTRY32, LPPROCESSENTRY32 );
DWORD GetParentProcessId( void );
BOOL  IsInstalled( DWORD id, PBYTE* base );
void  GetStatus( DWORD id, PBYTE base );
void  Inject( HANDLE hProcess );


int    installed	 __attribute__((dllimport));
DWORD  parent_pid	 __attribute__((dllimport));
Option option		 __attribute__((dllimport));
char   cfgname[MAX_PATH] __attribute__((dllimport));
char   cmdname[MAX_PATH] __attribute__((dllimport));
char   hstname[MAX_PATH] __attribute__((dllimport));
Status local		 __attribute__((dllimport));


int main( int argc, char* argv[] )
{
  DWORD  pid;
  HANDLE ph;
  PBYTE  base;
  BOOL	 active, update;
  char*  arg;
  char*  end;
  char*  opt;
  char	 state;
  char*  fname;
  unsigned long num;
  HKEY	 key, root;
  DWORD  exist;
  char	 cmdkey[MAX_PATH+4];
  BOOL	 hstfile;
  UCHAR* colour = NULL;
  int	 j;
  DWORD  len, type;
  char*  cmdpos;

  if (argc > 1)
  {
    if (strcmp( argv[1], "--help" ) == 0 ||
	((argv[1][0] == '-' || argv[1][0] == '/') && argv[1][1] == '?'))
    {
      help();
      return 0;
    }
    if (strcmp( argv[1], "--version" ) == 0)
    {
      puts( "CMDkey version " PVERS " (" PDATE ")." );
      return 0;
    }
  }

  pid = GetParentProcessId();
  active = IsInstalled( pid, &base );
  if (active && argc == 1)
  {
    GetStatus( pid, base );
    status();
    return 0;
  }
  update = (installed == -1);
  fname = (active) ? cmdname : cfgname;
  root = HKEY_CURRENT_USER;
  hstfile = FALSE;

  for (j = 1; j < argc; ++j)
  {
    if (argv[j][0] == '-' || argv[j][0] == '/')
    {
      if (!argv[j][1])
      {
	puts( "CMDkey: missing option." );
	return 1;
      }
      for (arg = argv[j] + 1; *arg; arg = end)
      {
	if (*arg == '-')
	  ++arg, state = 0;
	else if (*arg == '+')
	  ++arg, state = 1;
	else
	  state = (active) ? -1 : 1;
	if (!*arg)
	{
	  puts( "CMDkey: missing option." );
	  return 1;
	}
	opt = NULL;
	num = strtoul( arg + 1, &end, 10 );

	switch (tolower( *arg ))
	{
	  case '/': break;              // allow something like /b/e

	  case 'b': opt = &option.no_slash;      break;
	  case 'e': opt = &option.empty_hist;    break;
	  case 'g': opt = &option.silent;        break;
	  case 'o': opt = &option.overwrite;     break;
	  case 'r': opt = &option.auto_recall;   break;
	  case 't': opt = &option.disable_macro; break;
	  case '_': opt = &option.underscore;    break;

	  case 'z': option.disable_cmdkey = 1;   break;

	  case 'c':
	    if (end == arg + 1)
	    {
	      if (*end != ',')
	      {
		char temp = option.cursor_size[0];
		option.cursor_size[0] = option.cursor_size[1];
		option.cursor_size[1] = temp;
	      }
	      break;
	    }

	  case ',':
	    if (end == arg + 1)
	    {
	      puts( "CMDkey: missing cursor size." );
	      return 1;
	    }
	    if (num > 100)
	    {
	      puts( "CMDkey: cursor size must be between 0 and 100." );
	      return 1;
	    }
	    option.cursor_size[(*arg == ',')] = (char)num;
	  break;

	  case 'k':
	    end = arg + 1;
	    switch (*end | 0x20)
	    {
	      case 'c': colour = &option.cmd_col; break;
	      case 'r': colour = &option.rec_col; break;
	      case 'd': colour = &option.drv_col; break;
	      case 's': colour = &option.sep_col; break;
	      case 'p': colour = &option.dir_col; break;
	      case 'b': colour = &option.base_col; break;
	      case 'g': colour = &option.gt_col;  break;
	      case 'm': colour = &option.sel_col; break;
	      default:	opt = &option.nocolour; break;
	    }
	    if (opt)
	      break;
	    ++end;
	    if (!isxdigit( *end ))
	    {
	      printf( "CMDkey: expecting hexadecimal digit for -k%c.\n",
		      end[-1] | 0x20 );
	      return 1;
	    }
	    num = (*end > '9') ? (*end | 0x20) - 'a' + 10 : *end - '0';
	    if (isxdigit( *++end ))
	    {
	      num = num * 16 + ((*end > '9') ? (*end | 0x20) - 'a' + 10
					     : *end - '0');
	      ++end;
	    }
	    *colour = (UCHAR)num;
	  break;

	  case 'p':
	    end = arg + 1;	// on the odd chance of it being a digit
	    if (!*end)
	    {
	      puts( "CMDkey: missing macro ignore character." );
	      return 1;
	    }
	    option.ignore_char = *end++;
	  break;

	  case 'l':
	    if (end == arg + 1 || num == 0 || num > 255)
	    {
	      puts( "CMDkey: line length must be between 1 and 255." );
	      return 1;
	    }
	    option.min_length = (UCHAR)num;
	  break;

	  case 'h':
	    if (num > 255)
	    {
	      puts( "CMDkey: history size must be between 0 and 255." );
	      return 1;
	    }
	    option.histsize = (UCHAR)num;
	  break;

	  case 'i':
	    if (*arg == 'I')
	      root = HKEY_LOCAL_MACHINE;
	    len = GetModuleFileName( NULL, cmdkey + 2, sizeof(cmdkey) - 3 ) + 3;
	    strlwr( cmdkey + 2 );
	    cmdkey[0] = '&';
	    cmdkey[1] = '"';
	    // Replace exe with cmd (too bad if it's been renamed).
	    strcpy( cmdkey + len - 4, "cmd\"" );
	    // Add CMDkey to CMD.EXE's AutoRun setting, if not already present.
	    RegCreateKeyEx( root, CMDKEY, 0, "", REG_OPTION_NON_VOLATILE,
			    KEY_ALL_ACCESS, NULL, &key, &exist );
	    exist = 0;
	    RegQueryValueEx( key, AUTORUN, NULL, NULL, NULL, &exist );
	    opt = malloc( exist + len );
	    if (!opt)
	    {
	      puts( "CMDkey: where's all the memory gone?" );
	      return 1;
	    }
	    if (exist > sizeof(TCHAR))
	    {
	      RegQueryValueEx( key, AUTORUN, NULL, &type, (LPBYTE)opt, &exist );
	      cmdpos = strstr( opt, "cmdkey" );
	      if (!cmdpos)
	      {
		strcpy( opt + --exist, cmdkey );
		RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)opt, exist + len );
	      }
	      else
	      {
		char* end = cmdpos + 6;
		while (cmdpos != opt && *--cmdpos != '"') ;
		while (*end != '\0' && *end++ != '"') ;
		memmove( cmdpos + len - 1, end, exist - (end - opt) );
		memcpy( cmdpos, cmdkey + 1, len - 1 );
		RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)opt, strlen( opt ) + 1 );
	      }
	    }
	    else
	    {
	      RegSetValueEx( key, AUTORUN, 0, REG_SZ, (LPBYTE)cmdkey + 1, len );
	    }
	    RegCloseKey( key );
	    free( opt );
	    opt = NULL;
	    update = TRUE;
	  break;

	  case 'u':
	    if (*arg == 'U')
	      root = HKEY_LOCAL_MACHINE;
	    // Remove CMDkey from CMD.EXE's AutoRun setting.
	    RegCreateKeyEx( root, CMDKEY, 0, "", REG_OPTION_NON_VOLATILE,
			    KEY_ALL_ACCESS, NULL, &key, &exist );
	    exist = 0;
	    RegQueryValueEx( key, AUTORUN, NULL, NULL, NULL, &exist );
	    if (exist)
	    {
	      opt = malloc( exist );
	      if (!opt)
	      {
		puts( "CMDkey: where's all the memory gone?" );
		return 1;
	      }
	      RegQueryValueEx( key, AUTORUN, NULL, &type, (LPBYTE)opt, &exist );
	      cmdpos = strstr( opt, "cmdkey" );
	      if (cmdpos)
	      {
		len = cmdpos - opt + 6;
		while (cmdpos != opt && *--cmdpos != '"') ;
		while (opt[len] != '\0' && opt[len++] != '"') ;
		len -= cmdpos - opt;
		if (cmdpos == opt && exist == len + 1)
		  RegDeleteValue( key, AUTORUN );
		else
		{
		  if (cmdpos > opt && cmdpos[-1] == '&')
		    --cmdpos, ++len;
		  else if (cmdpos[len] == '&')
		    ++len;
		  memcpy( cmdpos, cmdpos + len, exist - len );
		  RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)opt, exist - len );
		}
	      }
	      free( opt );
	      opt = NULL;
	    }
	    RegCloseKey( key );
	    active = TRUE;
	  break;

	  case 'f':
	    hstfile = TRUE;
	    end = strchr( arg + 1, '\0' );
	    memcpy( hstname, arg + 1, end - arg );
	  break;

	  default:
	    printf( "CMDkey: invalid option: '%c'.\n", *arg );
	  return 1;
	}
	if (opt)
	{
	  if (state == -1)
	    *opt ^= 1;
	  else
	    *opt = state;
	}
      }
    }
    else
    {
      FILE* tmp = fopen( argv[j], "r" );
      if (tmp == NULL)
      {
	printf( "CMDkey: could not open \"%s\".\n", argv[j] );
	return 1;
      }
      fclose( tmp );
      strcpy( fname, argv[j] );
    }
  }
  if (update)
  {
    if (hstfile && *hstname)
      GetFullPathName( hstname, sizeof(hstname), hstname, NULL );
    if (*fname)
      GetFullPathName( fname, sizeof(cfgname), cfgname, NULL );
    else if (installed == -1)
    {
      // Let's just assume it ends with ".exe".
      j = GetModuleFileName( NULL, cfgname, sizeof(cfgname) ) - 3;
      strcpy( cfgname + j, "cfg" );
      if (!hstfile)
      {
	memcpy( hstname, cfgname, j );
	strcpy( hstname + j, "hst" );
	hstfile = TRUE;
      }
    }

    RegCreateKeyEx( root, REGKEY, 0, "", REG_OPTION_NON_VOLATILE,
		    KEY_ALL_ACCESS, NULL, &key, &exist );
    RegSetValueEx( key, "Options", 0, REG_BINARY, (LPBYTE)&option, sizeof(option) );
    RegSetValueEx( key, "Cmdfile", 0, REG_SZ, (LPBYTE)cfgname, strlen( cfgname ) + 1 );
    if (hstfile)
      RegSetValueEx( key, "Hstfile", 0, REG_SZ, (LPBYTE)hstname, strlen( hstname ) + 1 );
    RegCloseKey( key );
  }
  else if (hstfile)
  {
    if (*hstname)
      GetFullPathName( hstname, sizeof(hstname), hstname, NULL );
    else
    {
      *hstname = '-';
      hstname[1] = '\0';
    }
  }

  if (!active)
  {
    ph = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
    if (ph == NULL)
    {
      puts( "CMDkey: could not open parent process." );
      return 1;
    }
    Inject( ph );
    CloseHandle( ph );
  }

  return 0;
}


// Display the current status of CMDkey.
void status( void )
{
  char buf[4];
  char name[MAX_PATH+2];
  char hst[MAX_PATH+8];

  if (local.version != PVERX)
  {
    printf( "This CMDkey is version %x.%.2x, but installed edit.dll is ",
	    PVERX >> 8, PVERX & 0xFF );
    if (local.version == 0)
      puts( "unknown." );
    else
      printf( "%x.%.2x.\n", local.version >> 8, local.version & 0xFF );
    return;
  }

  if (option.histsize)
    itoa( option.histsize, buf, 10 );
  else
    strcpy( buf, "all" );

  if (*local.hstname)
    sprintf( hst, "\"%s\"", local.hstname );
  else
    strcpy( hst, "none" );

  if (*cfgname)
    sprintf( name, "\"%s\"", cfgname );
  else
    strcpy( name, "none" );

  printf( "\n"
	  "* %s mode is default.\n"
	  "* Cursor sizes: insert = %d%%, overwrite = %d%%.\n"
	  "* Backslash appending is %sabled.\n"
	  "* History search %s.\n"
	  "* Auto-recall is %sabled.\n"
	  "* Translation is %sabled.\n"
	  "* Error bell is %sabled.\n"
	  "* Ignore character is '%c'.\n"
	  "* Minimum history line length is %d.\n"
	  "* History will remember %s lines.\n"
	  "* History file: %s.\n"
	  "* Configuration file: %s.\n"
	  "* CMDkey is %sabled.\n",
	  (option.overwrite) ? "Overwrite" : "Insert",
	  option.cursor_size[0], option.cursor_size[1],
	  (option.no_slash) ? "dis" : "en",
	  (option.empty_hist)? "moves cursor to end" : "doesn't move cursor",
	  (option.auto_recall) ? "en" : "dis",
	  (option.disable_macro) ? "dis" : "en",
	  (option.silent) ? "dis" : "en",
	  option.ignore_char,
	  option.min_length,
	  buf,
	  hst,
	  name,
	  (local.enabled) ? "en" : "dis"
	);
}


// Search each process in the snapshot for id.
BOOL find_proc_id( HANDLE snap, DWORD id, LPPROCESSENTRY32 pe,
		   LPPROCESSENTRY32 ppe )
{
  BOOL fOk;

  pe->dwSize = sizeof(PROCESSENTRY32);
  for (fOk = Process32First( snap, pe ); fOk; fOk = Process32Next( snap, pe ))
  {
    if (pe->th32ProcessID == id)
      break;
    *ppe = *pe;
  }

  return fOk;
}


// Obtain the process identifier of the parent process; verify the architecture.
DWORD GetParentProcessId( void )
{
  HANDLE hSnap, ph;
  PROCESSENTRY32 pe, ppe;
  BOOL	 parent_wow64, me_wow64;
  typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)( HANDLE, PBOOL );
  LPFN_ISWOW64PROCESS fnIsWow64Process;

  hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if (hSnap == INVALID_HANDLE_VALUE)
  {
    puts( "CMDkey: unable to obtain process snapshot." );
    exit( 1 );
  }

  if (!find_proc_id( hSnap, GetCurrentProcessId(), &pe, &ppe ))
  {
    puts( "CMDkey: could not find my process ID." );
    exit( 1 );
  }
  if (ppe.th32ProcessID == pe.th32ParentProcessID)
    pe = ppe;
  else if (!find_proc_id( hSnap, pe.th32ParentProcessID, &pe, &ppe ))
  {
    puts( "CMDkey: could not find my parent's process ID." );
    exit( 1 );
  }
  parent_pid = pe.th32ParentProcessID;

  CloseHandle( hSnap );

  fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
			 GetModuleHandle( "kernel32.dll" ), "IsWow64Process" );
  if (fnIsWow64Process != NULL)
  {
    ph = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID );
    if (ph == NULL)
    {
      puts( "CMDkey: could not open parent process." );
      exit( 1 );
    }
    fnIsWow64Process( ph, &parent_wow64 );
    fnIsWow64Process( GetCurrentProcess(), &me_wow64 );
    CloseHandle( ph );

    if (parent_wow64 != me_wow64)
    {
      printf( "CMDkey: Cannot use %d-bit CMDkey with %d-bit CMD.EXE.\n",
	      (me_wow64) ? 32 : 64, (parent_wow64) ? 32 : 64 );
      exit( 1 );
    }
  }

  return pe.th32ProcessID;
}


// Determine if CMDkey is already installed in the parent.
BOOL IsInstalled( DWORD id, PBYTE* base )
{
  HANDLE	hModuleSnap;
  MODULEENTRY32 me;
  BOOL		fOk;

  *base = NULL;

  // Take a snapshot of all modules in the current process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, id );

  if (hModuleSnap == INVALID_HANDLE_VALUE)
  {
    puts( "CMDkey: unable to obtain module snapshot." );
    return FALSE;
  }

  // Fill the size of the structure before using it.
  me.dwSize = sizeof(MODULEENTRY32);

  // Walk the module list of the modules
  for (fOk = Module32First( hModuleSnap, &me ); fOk;
       fOk = Module32Next( hModuleSnap, &me ))
  {
    if (stricmp( me.szModule, "edit.dll" ) == 0)
    {
      *base = me.modBaseAddr;
      break;
    }
  }
  CloseHandle( hModuleSnap );

  return fOk;
}


// Read the local variables from the parent process.
void GetStatus( DWORD id, PBYTE base )
{
  Status* plocal = NULL;
  HANDLE parent = OpenProcess( PROCESS_VM_READ, FALSE, id );
  local.version = 0;
  if (parent)
  {
    PIMAGE_DOS_HEADER	    pDosHeader;
    PIMAGE_NT_HEADERS	    pNTHeader;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    PDWORD ExportNameTable;
    PBYTE  ExportBase;
    DWORD  ord;
    BYTE   buf[512];

    // Locate the "local" export.
#define MakeVA( cast, base, addValue ) \
  (cast)((DWORD_PTR)(base) + (DWORD_PTR)(addValue))
    ReadProcessMemory( parent, base, buf, sizeof(buf), NULL );
    pDosHeader = (PIMAGE_DOS_HEADER)buf;
    pNTHeader = MakeVA( PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew );
    pExportDir = MakeVA( PIMAGE_EXPORT_DIRECTORY, base,
			 pNTHeader->OptionalHeader.
			  DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].
			   VirtualAddress );

    // Bail out if the RVA of the exports section is 0 (it doesn't exist).
    // This should only happen if there's another edit.dll injected before us.
    if ((PBYTE)pExportDir == base)
    {
      CloseHandle( parent );
      return;
    }

    ReadProcessMemory( parent, pExportDir, buf, sizeof(buf), NULL );
    ExportBase = buf + (base - (PBYTE)pExportDir);
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)buf;
    ExportNameTable = MakeVA( PDWORD, ExportBase, pExportDir->AddressOfNames );
    for (ord = pExportDir->NumberOfNames; (int)--ord >= 0;)
    {
      PSTR pszExportName = MakeVA( PSTR, ExportBase, ExportNameTable[ord] );
      if (strcmp( pszExportName, "local" ) == 0)
      {
	WORD* ExportOrdinalTable = MakeVA( WORD*, ExportBase,
					   pExportDir->AddressOfNameOrdinals );
	ord = ExportOrdinalTable[ord];
	DWORD* ExportFunctionTable = MakeVA( DWORD*, ExportBase,
					     pExportDir->AddressOfFunctions );
	plocal = MakeVA( Status*, base, ExportFunctionTable[ord] );
	break;
      }
    }
    if (plocal)
      ReadProcessMemory( parent, plocal, &local, sizeof(local), NULL );
    else
    {
      // Read the timestamp in the header to determine the released version.
      DWORD tstamp;
      ReadProcessMemory( parent, base + 0x88, &tstamp, 4, NULL );
      switch (tstamp)
      {
	case 0x458cdf26: local.version = 0x100; break;
	case 0x45ff9109: local.version = 0x101; break;
	case 0x4c494fe9: local.version = 0x102; break;
      }
    }
    CloseHandle( parent );
  }
}


// Inject code into the target process to load our DLL.
void Inject( HANDLE hProcess )
{
  WCHAR  dll[MAX_PATH];
  LPWSTR name, path;
  DWORD  len;
  LPVOID mem;
  LPVOID LLW;
  HANDLE thread;

  len = GetModuleFileNameW( NULL, dll, MAX_PATH ) + 1;
  for (name = path = dll; *path; ++path)
    if (*path == '\\')
      name = path + 1;
  wcscpy( name, L"edit.dll" );

  LLW = GetProcAddress( GetModuleHandle( "kernel32.dll" ), "LoadLibraryW" );
  mem = VirtualAllocEx( hProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE );
  WriteProcessMemory( hProcess, mem, dll, len * sizeof(WCHAR), NULL );
  thread = CreateRemoteThread( hProcess, NULL, 4096, LLW, mem, 0, NULL );
  WaitForSingleObject( thread, INFINITE );
  CloseHandle( thread );
  VirtualFreeEx( hProcess, mem, 0, MEM_RELEASE );
}


void help( void )
{
  puts(
  "CMDkey by Jason Hood <jadoxa@yahoo.com.au>.\n"
  "Version " PVERS " (" PDATE ").  Freeware.\n"
  "http://cmdkey.adoxa.vze.com/\n"
  "\n"
  "Provide enhanced command line editing for CMD.EXE.\n"
  "\n"
  "cmdkey [-begkortz_] [-c[INS][,OVR]] [-h[HIST]] [-lLEN] [-pCHAR]\n"
  "       [-kcCMD] [-kmSEL] [-krREC] [-kdDRV] [-ksSEP] [-kpDIR] [-kbBASE] [-kgGT]\n"
  "       [-f[HISTFILE]] [CFGFILE] [-iu]\n"
  "\n"
  "    -b\t\tdisable backslash appending for completed directories\n"
  "    -c\t\tswap insert and overwrite cursors, or set their size\n"
  "    -e\t\tsearching history will move cursor to the end\n"
  "    -f\t\tfile to store persistent history (none means don't store)\n"
  "    -g\t\tsilent mode\n"
  "    -h\t\tremember the last HIST commands (0 will remember everything)\n"
  "    -k\t\tdisable colouring\n"
  "    -l\t\tminimum line length to remember\n"
  "    -o\t\tdefault overwrite mode\n"
  "    -p\t\tuse CHAR to disable translation for the current line\n"
  "    -r\t\tdefault auto-recall mode\n"
  "    -t\t\tdisable translation\n"
  "    -z\t\tdisable CMDkey\n"
  "    -_\t\tunderscore is not part of a word\n"
  "    CFGFILE\tfile containing CMDkey commands and/or history lines\n"
  "\n"
  "    CMD\t\tcolour of the command line\n"
  "    SEL\t\tcolour of selected text\n"
  "    REC\t\tcolour when recording a macro\n"
  "    DRV\t\tcolour of the prompt's drive letter and colon\n"
  "    SEP\t\tcolour of the prompt's directory separator\n"
  "    DIR\t\tcolour of the prompt's directory\n"
  "    BASE\tcolour of the prompt's base directory\n"
  "    GT\t\tcolour of the prompt's greater-than sign\n"
  "\n"
  "    -i\t\tinstall (add to CMD's AutoRun registry entry and make the\n"
  "      \t\tcurrent options the default)\n"
  "    -u\t\tuninstall (remove from AutoRun)\n"
  "    -I -U\tuse local machine instead of current user\n"
  "\n"
  "CMDkey with no arguments will either install itself into the current CMD.EXE or\n"
  "display the status of the already running instance.\n"
  "When CMDkey is already running options -begkort_ will toggle the current state;\n"
  "prefix them with '+' to explicitly turn on (set behaviour indicated above) or\n"
  "with '-' to turn off (set default behaviour).  Eg: \"cmdkey -+b-g\" will disable\n"
  "backslash appending and enable the beep, irrespective of the current state.\n"
  "A colour is one or two hex digits; see CMD's COLOR help."
      );
}
