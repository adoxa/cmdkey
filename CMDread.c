/*
  CMDread.c - Enhanced command line editing for CMD.EXE.

  Jason Hood, 24 October to 21 November, 2005 and 20 to 23 December, 2006.

  Injection code derived from Console Manager by Sergey Oblomov (hoopoepg).
  Additional information from "Process-wide API spying - an ultimate hack" By
  Anton Bassov's article in "The Code Project" (use of OpenThread).

  v1.02, 23 July, 2010:
  + add -I/-U to use HKLM.

  v2.00, 22 July to 8 August, 2011:
  * compile cleanly with GCC 4;
  * slight improvements in finding parent process;
  * install as a batch file (CMDread.cmd) to improve load time for "cmd /c";
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

  14 & 15 June, 2012:
  * modified injection (use VirtualAllocEx method, not stack);
  + 64-bit version;
  - search for the local export (improved future-proofing);
  - install/uninstall will replace/remove a string containing "cmdread" or
    "cmdkey".

  21 May, 2013:
  - fixed status in 64-bit version.

  27 May, 2013:
  * use CreateRemoteThread injection method (and LoadLibraryW);
  - prevent 32/64 mismatch.

  6 June, 2013:
  * renamed from CMDkey to CMDread to avoid potential confusion/conflict with
    Microsoft's Cmdkey.

  v2.10, 11 to 24 June, 2013:
  * use Unicode;
  + -q option to set prefix character to always update the history line;
  - verify the registry key is created (HKLM requires admin privileges);
  * remove the initial blank line in the stats, add underscore setting, add
    processor type;
  * use %USERPROFILE% as the default config/history path.

  v2.11, 4 July, 2013:
  - fixed file names (GetFullPathNameW doesn't like the same buffers).

  v2.12, 10 July, 2013:
  * only write to the registry with an explicit -i;
  * read the options here, not from edit.
*/

#define PDATE L"10 July, 2013"

#include "CMDread.h"
#include "version.h"
#include <tlhelp32.h>

#ifndef offsetof
# define offsetof(type, member) (size_t)(&(((type*)0)->member))
#endif

#ifdef __MINGW32__
int _CRT_glob = 0;
#endif


#define CMDREAD L"Software\\Microsoft\\Command Processor"
#define AUTORUN L"AutoRun"

#ifdef _WIN64
#define ARCH L"amd64"
#define EDITDLL L"edit_" ARCH L".dll"
#else
#define ARCH L"x86"
#define EDITDLL L"edit.dll"
#endif


void status( void );
void help( void );

BOOL  find_proc_id( HANDLE snap, DWORD id, LPPROCESSENTRY32, LPPROCESSENTRY32 );
DWORD GetParentProcessId( void );
BOOL  IsInstalled( DWORD id, PBYTE* base );
void  GetStatus( DWORD id, PBYTE base );
void  Inject( HANDLE hProcess );
BOOL  GetRegKey( LPCWSTR, HKEY, LPCWSTR, PHKEY, LPDWORD );
BOOL  ReadOptions( HKEY, BOOL );


__declspec(dllimport) DWORD  parent_pid;
__declspec(dllimport) Option option;
		      WCHAR  cmdname[MAX_PATH];
__declspec(dllimport) WCHAR  cfgname[MAX_PATH];
__declspec(dllimport) WCHAR  hstname[MAX_PATH];
__declspec(dllimport) BOOL   cmd_history;
__declspec(dllimport) Status local;


#if defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)
// Thanks to Coder for Life.
// http://www.coderforlife.com/projects/utilities/
int wmain();
void __wgetmainargs( int*, wchar_t***, wchar_t***, int, int* );
int main()
{
  wchar_t **argv, **envp;
  int argc, si = 0;
  __wgetmainargs( &argc, &argv, &envp, 0, &si );
  return wmain( argc, argv );
}
#endif

int wmain( int argc, wchar_t* argv[] )
{
  DWORD  pid;
  HANDLE ph;
  PBYTE  base;
  BOOL	 active, update;
  LPWSTR arg;
  LPWSTR end;
  char*  opt;
  LPWSTR ops;
  char	 state;
  LPWSTR hname;
  ULONG  num;
  HKEY	 key, root;
  DWORD  exist;
  WCHAR  CMDread[MAX_PATH+4];
  UCHAR* colour = NULL;
  int	 j;
  DWORD  len, type;
  LPWSTR cmdpos;
  char	 cp[16];

  // Thanks to Michael Kaplan.
  // http://blogs.msdn.com/b/michkap/archive/2010/10/07/10072032.aspx
  // However, it seems the fputws in MSVCRT.DLL (Win7 HP 64-bit) doesn't work
  // with _O_U16TEXT.
  if (_isatty( 1 ))
    _setmode( 1, _O_U16TEXT );

  // Set the locale code page so wide-string conversions work as expected.
  sprintf( cp, ".%u", GetConsoleOutputCP() );
  setlocale( LC_CTYPE, cp );

  if (argc > 1)
  {
    if (wcscmp( argv[1], L"--help" ) == 0 ||
	((argv[1][0] == '-' || argv[1][0] == '/') && argv[1][1] == '?'))
    {
      help();
      return 0;
    }
    if (wcscmp( argv[1], L"--version" ) == 0)
    {
      _putws( L"CMDread (" ARCH L") version " PVERS L" (" PDATE L")." );
      return 0;
    }
  }

  pid = GetParentProcessId();
  active = IsInstalled( pid, &base );
  if (!ReadOptions( HKEY_CURRENT_USER, active ))
    ReadOptions( HKEY_LOCAL_MACHINE, active );
  if (active)
  {
    GetStatus( pid, base );
    if (argc == 1)
    {
      status();
      return 0;
    }
  }

  update = FALSE;
  hname = NULL;
  root = HKEY_CURRENT_USER;

  for (j = 1; j < argc; ++j)
  {
    if (argv[j][0] == '-' || argv[j][0] == '/')
    {
      if (!argv[j][1])
      {
	wprintf( L"CMDread: missing option (argument %d).\n", j );
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
	  wprintf( L"CMDread: missing option (argument %d).\n", j );
	  return 1;
	}
	opt = NULL;
	num = wcstoul( arg + 1, &end, 10 );

	switch (towlower( *arg ))
	{
	  case '/': break;              // allow something like /b/e

	  case 'b': opt = &option.no_slash;      break;
	  case 'e': opt = &option.empty_hist;    break;
	  case 'g': opt = &option.silent;        break;
	  case 'o': opt = &option.overwrite;     break;
	  case 'r': opt = &option.auto_recall;   break;
	  case 't': opt = &option.disable_macro; break;
	  case '_': opt = &option.underscore;    break;

	  case 'z': option.disable_CMDread = 1;  break;

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
	      _putws( L"CMDread: missing cursor size." );
	      return 1;
	    }
	    if (num > 100)
	    {
	      _putws( L"CMDread: cursor size must be between 0 and 100." );
	      return 1;
	    }
	    option.cursor_size[(*arg == ',')] = (char)num;
	  break;

	  case 'k':
	    end = arg + 1;
	    switch (*end | 0x20)
	    {
	      case 'c': colour = &option.cmd_col;  break;
	      case 'r': colour = &option.rec_col;  break;
	      case 'd': colour = &option.drv_col;  break;
	      case 's': colour = &option.sep_col;  break;
	      case 'p': colour = &option.dir_col;  break;
	      case 'b': colour = &option.base_col; break;
	      case 'g': colour = &option.gt_col;   break;
	      case 'm': colour = &option.sel_col;  break;
	      default:	opt    = &option.nocolour; break;
	    }
	    if (opt)
	      break;
	    ++end;
	    if (!iswxdigit( *end ))
	    {
	      wprintf( L"CMDread: expecting hexadecimal digit for -k%c.\n",
		       end[-1] | 0x20 );
	      return 1;
	    }
	    num = (*end > '9') ? (*end | 0x20) - 'a' + 10 : *end - '0';
	    if (iswxdigit( *++end ))
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
	      _putws( L"CMDread: missing macro ignore character." );
	      return 1;
	    }
	    option.ignore_char = *end++;
	  break;

	  case 'q':
	    end = arg + 1;	// on the odd chance of it being a digit
	    if (!*end)
	    {
	      _putws( L"CMDread: missing history update character." );
	      return 1;
	    }
	    option.update_char = *end++;
	  break;

	  case 'l':
	    if (end == arg + 1 || num == 0 || num > 255)
	    {
	      _putws( L"CMDread: line length must be between 1 and 255." );
	      return 1;
	    }
	    option.min_length = (UCHAR)num;
	  break;

	  case 'h':
	    if (num > 255)
	    {
	      _putws( L"CMDread: history size must be between 0 and 255." );
	      return 1;
	    }
	    option.histsize = (UCHAR)num;
	  break;

	  case 'i':
	    if (*arg == 'I')
	      root = HKEY_LOCAL_MACHINE;
	    len = GetModuleFileName( NULL, CMDread + 2, MAX_PATH ) + 2;
	    _wcslwr( CMDread + 2 );
	    CMDread[0] = '&';
	    CMDread[1] = '"';
	    // Strip the processor type (too bad if it's been renamed).
	    while (CMDread[--len] != '_' && CMDread[len] != '\\' && len != 0) ;
	    wcscpy( CMDread + len, L".cmd\"" );
	    len += 5;
	    // Add CMDread to CMD.EXE's AutoRun setting, if not already present.
	    if (!GetRegKey( L"add AutoRun", root, CMDREAD, &key, &exist ))
	      return 1;
	    exist = 0;
	    RegQueryValueEx( key, AUTORUN, NULL, NULL, NULL, &exist );
	    ops = malloc( exist + WSZ(len) );
	    if (!ops)
	    {
	      _putws( L"CMDread: where's all the memory gone?" );
	      return 1;
	    }
	    if (exist > sizeof(WCHAR))
	    {
	      RegQueryValueEx( key, AUTORUN, NULL, &type, (LPBYTE)ops, &exist );
	      cmdpos = wcsstr( ops, L"cmdread" );
	      if (!cmdpos)
		cmdpos = wcsstr( ops, L"cmdkey" );
	      if (!cmdpos)
	      {
		wcscpy( ops + --exist, CMDread );
		RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)ops,
			       exist + WSZ(len) );
	      }
	      else
	      {
		LPWSTR end = cmdpos + 6;
		while (cmdpos != ops && *--cmdpos != '"') ;
		while (*end != '\0' && *end++ != '"') ;
		memmove( cmdpos + len - 1, end, exist - WSZ(end - ops) );
		memcpy( cmdpos, CMDread + 1, WSZ(len - 1) );
		RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)ops,
			       WSZ(wcslen( ops ) + 1) );
	      }
	    }
	    else
	    {
	      RegSetValueEx( key, AUTORUN, 0, REG_SZ, (LPBYTE)(CMDread + 1),
			     WSZ(len) );
	    }
	    RegCloseKey( key );
	    free( ops );
	    update = TRUE;
	  break;

	  case 'u':
	    if (*arg == 'U')
	      root = HKEY_LOCAL_MACHINE;
	    // Remove CMDread from CMD.EXE's AutoRun setting.
	    if (!GetRegKey( L"remove AutoRun", root, CMDREAD, &key, &exist ))
	      return 1;
	    exist = 0;
	    RegQueryValueEx( key, AUTORUN, NULL, NULL, NULL, &exist );
	    if (exist)
	    {
	      ops = malloc( exist );
	      if (!ops)
	      {
		_putws( L"CMDread: where's all the memory gone?" );
		return 1;
	      }
	      RegQueryValueEx( key, AUTORUN, NULL, &type, (LPBYTE)ops, &exist );
	      cmdpos = wcsstr( ops, L"cmdread" );
	      if (!cmdpos)
		cmdpos = wcsstr( ops, L"cmdkey" );
	      if (cmdpos)
	      {
		len = cmdpos - ops + 6;
		while (cmdpos != ops && *--cmdpos != '"') ;
		while (ops[len] != '\0' && ops[len++] != '"') ;
		len -= cmdpos - ops;
		if (cmdpos == ops && exist == WSZ(len + 1))
		  RegDeleteValue( key, AUTORUN );
		else
		{
		  if (cmdpos > ops && cmdpos[-1] == '&')
		    --cmdpos, ++len;
		  else if (cmdpos[len] == '&')
		    ++len;
		  memcpy( cmdpos, cmdpos + len, exist - WSZ(len) );
		  RegSetValueEx( key, AUTORUN, 0, type, (LPBYTE)ops,
				 exist - WSZ(len) );
		}
	      }
	      free( ops );
	    }
	    RegCloseKey( key );
	    active = TRUE;
	  break;

	  case 'f':
	    hname = arg + 1;
	    end = wcschr( arg + 1, '\0' );
	    cmd_history = TRUE;
	  break;

	  default:
	    wprintf( L"CMDread: invalid option: '%c'.\n", *arg );
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
      FILE* tmp = _wfopen( argv[j], L"r" );
      if (tmp == NULL)
      {
	wprintf( L"CMDread: could not open \"%s\".\n", argv[j] );
	return 1;
      }
      fclose( tmp );
      wcscpy( cfgname, argv[j] );
    }
  }
  if (hname)
  {
    if (*hname)
      GetFullPathName( hname, lenof(local.hstname), local.hstname, NULL );
    else
    {
      local.hstname[0] = '-';
      local.hstname[1] = '\0';
      cmd_history = FALSE;
    }
  }
  if (hname || !active)
    wcscpy( hstname, local.hstname );
  if (!active && !*cfgname)
    wcscpy( cfgname, cmdname );

  if (update)
  {
    if (!GetRegKey( L"update options", root, REGKEY, &key, &exist ))
      return 1;

    if (*cfgname)
      GetFullPathName( cfgname, lenof(cmdname), cmdname, NULL );

    RegSetValueEx( key, L"Options", 0, REG_BINARY, (LPBYTE)&option,
		   sizeof(option) );
    RegSetValueEx( key, L"Cmdfile", 0, REG_SZ, (LPBYTE)cmdname,
		   WSZ(wcslen( cmdname ) + 1) );
    RegSetValueEx( key, L"Hstfile", 0, REG_SZ, (LPBYTE)local.hstname,
		   WSZ(wcslen( local.hstname ) + 1) );
    RegCloseKey( key );
  }

  if (!active)
  {
    ph = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
    if (ph == NULL)
    {
      _putws( L"CMDread: could not open parent process." );
      return 1;
    }
    Inject( ph );
    CloseHandle( ph );
  }

  return 0;
}


BOOL ReadOptions( HKEY root, BOOL cfg_only )
{
  HKEY	key;
  DWORD exist;

  if (RegOpenKeyEx( root, REGKEY, 0, KEY_QUERY_VALUE, &key ) != ERROR_SUCCESS)
  {
    if (root == HKEY_LOCAL_MACHINE)
    {
      exist = GetEnvironmentVariable( L"USERPROFILE", cmdname, lenof(cmdname) );
      wcscpy( cmdname + exist, L"\\CMDread.cfg" );
      memcpy( local.hstname, cmdname, WSZ(exist + 9) );
      wcscpy( local.hstname + exist + 9, L"hst" );
    }
    return FALSE;
  }

  exist = sizeof(cmdname);
  RegQueryValueEx( key, L"Cmdfile", NULL, NULL, (LPBYTE)cmdname, &exist );
  exist = sizeof(local.hstname);
  RegQueryValueEx( key, L"Hstfile", NULL, NULL, (LPBYTE)local.hstname, &exist );

  if (!cfg_only)
  {
    exist = sizeof(option);
    RegQueryValueEx( key, L"Options", NULL, NULL, (LPBYTE)&option, &exist );
    if (exist != sizeof(option))
    {
      // Update options from earlier versions (I really gotta stop being lazy
      // using binary writes...).
      if (exist == offsetof(Option, base_col))
	option.base_col = option.dir_col;
      if (exist == offsetof(Option, ignore_char))
	option.ignore_char = option.old_ignore_char;
    }
  }
  RegCloseKey( key );

  return TRUE;
}


// Display the current status of CMDread.
void status( void )
{
  WCHAR buf[4];
  WCHAR name[MAX_PATH+2];
  WCHAR hst[MAX_PATH+8];

  if (local.version != PVERX)
  {
    wprintf( L"This CMDread is version %x.%.2x, but installed edit DLL is ",
	     PVERX >> 8, PVERX & 0xFF );
    if (local.version == 0)
      _putws( L"unknown." );
    else
      wprintf( L"%x.%.2x.\n", local.version >> 8, local.version & 0xFF );
    return;
  }

  if (option.histsize)
    _itow( option.histsize, buf, 10 );
  else
    wcscpy( buf, L"all" );

  if (*local.hstname)
    _snwprintf( hst, lenof(hst), L"\"%s\"", local.hstname );
  else
    wcscpy( hst, L"none" );

  if (*cmdname)
    _snwprintf( name, lenof(name), L"\"%s\"", cmdname );
  else
    wcscpy( name, L"none" );

  wprintf( L"* %s mode is default.\n"
	   L"* Cursor sizes: insert = %d%%, overwrite = %d%%.\n"
	   L"* Backslash appending is %sabled.\n"
	   L"* History search %s.\n"
	   L"* Auto-recall is %sabled.\n"
	   L"* Translation is %sabled.\n"
	   L"* Error bell is %sabled.\n"
	   L"* Underscore is%s part of a word.\n"
	   L"* Ignore character is '%c'.\n"
	   L"* Update character is '%c'.\n"
	   L"* Minimum history line length is %d.\n"
	   L"* History will remember %s lines.\n"
	   L"* History file: %s.\n"
	   L"* Configuration file: %s.\n"
	   L"* CMDread (" ARCH L") is %sabled.\n",
	   (option.overwrite) ? L"Overwrite" : L"Insert",
	   option.cursor_size[0], option.cursor_size[1],
	   (option.no_slash) ? L"dis" : L"en",
	   (option.empty_hist)? L"moves cursor to end" : L"doesn't move cursor",
	   (option.auto_recall) ? L"en" : L"dis",
	   (option.disable_macro) ? L"dis" : L"en",
	   (option.silent) ? L"dis" : L"en",
	   (option.underscore) ? L"" : L" not",
	   option.ignore_char,
	   option.update_char,
	   option.min_length,
	   buf,
	   hst,
	   name,
	   (local.enabled) ? L"en" : L"dis"
	 );
}


// Create or open registry key "root\subkey", checking that it succeeded.
BOOL GetRegKey( LPCWSTR op, HKEY root, LPCWSTR subkey, PHKEY key, LPDWORD disp )
{
  if (ERROR_SUCCESS != RegCreateKeyEx( root, subkey, 0, NULL, 0,
				       KEY_ALL_ACCESS, NULL, key, disp ))
  {
    wprintf( L"CMDread: could not %s", op );
    if (root == HKEY_LOCAL_MACHINE)
      wprintf( L" (perhaps use -i/-u, or run as admin)" );
    _putws( L"." );
    return FALSE;
  }
  return TRUE;
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
    _putws( L"CMDread: unable to obtain process snapshot." );
    exit( 1 );
  }

  if (!find_proc_id( hSnap, GetCurrentProcessId(), &pe, &ppe ))
  {
    _putws( L"CMDread: could not find my process ID." );
    exit( 1 );
  }
  if (ppe.th32ProcessID == pe.th32ParentProcessID)
    pe = ppe;
  else if (!find_proc_id( hSnap, pe.th32ParentProcessID, &pe, &ppe ))
  {
    _putws( L"CMDread: could not find my parent's process ID." );
    exit( 1 );
  }
  parent_pid = pe.th32ParentProcessID;

  CloseHandle( hSnap );

  fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
			GetModuleHandle( L"kernel32.dll" ), "IsWow64Process" );
  if (fnIsWow64Process != NULL)
  {
    ph = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID );
    if (ph == NULL)
    {
      _putws( L"CMDread: could not open parent process." );
      exit( 1 );
    }
    fnIsWow64Process( ph, &parent_wow64 );
    fnIsWow64Process( GetCurrentProcess(), &me_wow64 );
    CloseHandle( ph );

    if (parent_wow64 != me_wow64)
    {
      wprintf( L"CMDread: Cannot use %d-bit CMDread with %d-bit CMD.EXE.\n",
	       (me_wow64) ? 32 : 64, (parent_wow64) ? 32 : 64 );
      exit( 1 );
    }
  }

  return pe.th32ProcessID;
}


// Determine if CMDread is already installed in the parent.
BOOL IsInstalled( DWORD id, PBYTE* base )
{
  HANDLE hModuleSnap;
  MODULEENTRY32 me;
  BOOL	 fOk;

  *base = NULL;

  // Take a snapshot of all modules in the current process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, id );

  if (hModuleSnap == INVALID_HANDLE_VALUE)
  {
    _putws( L"CMDread: unable to obtain module snapshot." );
    return FALSE;
  }

  // Fill the size of the structure before using it.
  me.dwSize = sizeof(MODULEENTRY32);

  // Walk the module list of the modules
  for (fOk = Module32First( hModuleSnap, &me ); fOk;
       fOk = Module32Next( hModuleSnap, &me ))
  {
    if (_wcsicmp( me.szModule, EDITDLL ) == 0)
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
    // This should only happen if there's another edit DLL injected before us.
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
	DWORD* ExportFunctionTable = MakeVA( DWORD*, ExportBase,
					     pExportDir->AddressOfFunctions );
	ord = ExportOrdinalTable[ord];
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

  len = GetModuleFileName( NULL, dll, lenof(dll) ) + 1;
  for (name = path = dll; *path; ++path)
    if (*path == '\\')
      name = path + 1;
  wcscpy( name, EDITDLL );

  LLW = GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "LoadLibraryW" );
  mem = VirtualAllocEx( hProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE );
  WriteProcessMemory( hProcess, mem, dll, WSZ(len), NULL );
  thread = CreateRemoteThread( hProcess, NULL, 4096, LLW, mem, 0, NULL );
  WaitForSingleObject( thread, INFINITE );
  CloseHandle( thread );
  VirtualFreeEx( hProcess, mem, 0, MEM_RELEASE );
}


void help( void )
{
  _putws(
  L"CMDread by Jason Hood <jadoxa@yahoo.com.au>.\n"
  L"Version " PVERS L" (" PDATE L").  Freeware.\n"
  L"http://cmdkey.adoxa.vze.com/\n"
  L"\n"
#ifdef _WIN64
  L"Provide enhanced command line editing for CMD.EXE (64-bit).\n"
#else
  L"Provide enhanced command line editing for CMD.EXE (32-bit).\n"
#endif
  L"\n"
  L"CMDread [-begkortz_] [-c[INS][,OVR]] [-h[HIST]] [-lLEN] [-pCHAR] [-qCHAR]\n"
  L"        [-kcCMD] [-kmSEL] [-krREC] [-kdDRV] [-ksSEP] [-kpDIR] [-kbBASE] [-kgGT]\n"
  L"        [-f[HISTFILE]] [CFGFILE] [-iIuU]\n"
  L"\n"
  L"    -b\t\tdisable backslash appending for completed directories\n"
  L"    -c\t\tswap insert and overwrite cursors, or set their size\n"
  L"    -e\t\tsearching history will move cursor to the end\n"
  L"    -f\t\tfile to store persistent history (none means don't store)\n"
  L"    -g\t\tsilent mode\n"
  L"    -h\t\tremember the last HIST commands (0 will remember everything)\n"
  L"    -k\t\tdisable colouring\n"
  L"    -l\t\tminimum line length to remember\n"
  L"    -o\t\tdefault overwrite mode\n"
  L"    -p\t\tuse CHAR to disable translation for the current line\n"
  L"    -q\t\tuse CHAR to update the line in the history\n"
  L"    -r\t\tdefault auto-recall mode\n"
  L"    -t\t\tdisable translation\n"
  L"    -z\t\tdisable CMDread\n"
  L"    -_\t\tunderscore is not part of a word\n"
  L"    CFGFILE\tfile containing CMDread commands and/or history lines\n"
  L"\n"
  L"    CMD\t\tcolour of the command line\n"
  L"    SEL\t\tcolour of selected text\n"
  L"    REC\t\tcolour when recording a macro\n"
  L"    DRV\t\tcolour of the prompt's drive letter and colon\n"
  L"    SEP\t\tcolour of the prompt's directory separator\n"
  L"    DIR\t\tcolour of the prompt's directory\n"
  L"    BASE\tcolour of the prompt's base directory\n"
  L"    GT\t\tcolour of the prompt's greater-than sign\n"
  L"\n"
  L"    -i\t\tinstall (add to CMD's AutoRun registry entry and make the\n"
  L"      \t\tcurrent options the default)\n"
  L"    -u\t\tuninstall (remove from AutoRun)\n"
  L"    -I -U\tuse local machine instead of current user (if permitted)\n" );
  _putws( // too big for a single statement?
  L"CMDread with no arguments will either install itself into the current CMD.EXE\n"
  L"or display the status of the already running instance.  When CMDread is already\n"
  L"running, options -begkort_ will toggle the current state; prefix them with '+'\n"
  L"to explicitly turn on (set behaviour indicated above) or with '-' to turn off\n"
  L"(set default behaviour).  Eg: \"CMDread -+b-g\" will disable backslash appending\n"
  L"and enable the beep, irrespective of the current state.\n"
  L"A colour is one or two hex digits; see CMD's COLOR help."
      );
}
