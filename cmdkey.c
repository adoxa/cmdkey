/*
  cmdkey.c - Enhanced command line editing for CMD.EXE.

  Jason Hood, 24 October to 21 November, 2005 and 20 to 23 December, 2006.

  Injection code derived from Console Manager by Sergey Oblomov (hoopoepg).
  Additional information from "Process-wide API spying - an ultimate hack" By
  Anton Bassov's article in "The Code Project" (use of OpenThread).

  v1.02, 23 July, 2010:
  + add -I/-U to use HKLM.
*/

#define PVERS "1.02"
#define PDATE "23 July, 2010"

// Uncomment the below when using NT, which doesn't have the tool help library.
// This means I can't (easily) find the parent process, so it starts a new
// instance of CMD with -i and assumes installed without it.
//#define NT4

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef NT4
#include <tlhelp32.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cmdkey.h"

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

#ifndef NT4
BOOL  find_proc_id( HANDLE snap, DWORD id, LPPROCESSENTRY32 pe );
DWORD GetParentProcessInfo( LPPROCESS_INFORMATION pInfo );
BOOL  IsInstalled( DWORD id );
#endif
void  Inject( LPPROCESS_INFORMATION pinfo );


BOOL   installed	 __attribute__((dllimport));
BOOL   is_enabled	 __attribute__((dllimport));
Option option		 __attribute__((dllimport));
char   cfgname[MAX_PATH] __attribute__((dllimport));
char   cmdname[MAX_PATH] __attribute__((dllimport));


int main( int argc, char* argv[] )
{
  PROCESS_INFORMATION pinfo;
  BOOL	 active, update;
  char*  arg;
  char*  end;
  char*  opt;
  char	 state, lastopt;
  char*  fname;
  unsigned long num;
  HKEY	 key, root;
  DWORD  exist;
  char	 cmdkey[MAX_PATH+4];
  UCHAR* colour = NULL;
  int	 j;
#ifndef NT4
  DWORD  len, type;
  char*  cmdpos;
#endif

  if (argc > 1 &&
      (strcmp( argv[1], "--help" ) == 0 ||
       ((argv[1][0] == '-' || argv[1][0] == '/') && argv[1][1] == '?')))
  {
    help();
    return 0;
  }

#ifdef NT4
  if (argc == 1)
  {
    status();
    return 0;
  }
  update = FALSE;
  active = TRUE;
  fname  = "";
#else
  active = IsInstalled( GetParentProcessInfo( &pinfo ) );
  if (active && argc == 1)
  {
    status();
    return 0;
  }
  update = (!installed && argc > 1);
  fname = (active) ? cmdname : cfgname;
#endif
  root = HKEY_CURRENT_USER;

  for (j = 1; j < argc; ++j)
  {
    if (argv[j][0] == '-' || argv[j][0] == '/')
    {
      if (!argv[j][1])
      {
	puts( "CMDkey: missing option." );
	return 1;
      }
      lastopt = 0;
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

	switch (*arg | 0x20)
	{
	  case '/': break;              // allow something like /b/e

	  case 'b': opt = &option.no_slash;      break;
	  case 'e': opt = &option.empty_hist;    break;
	  case 'g': opt = &option.silent;        break;
	  case 'o': opt = &option.overwrite;     break;
	  case 'r': opt = &option.auto_recall;   break;
	  case 't': opt = &option.disable_macro; break;

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
	    lastopt = 'c';

	  case ',':
	    if (lastopt == 'c')
	    {
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
	    }
	    else if (lastopt == 'k')
	    {
	      if (++colour > &option.gt_col)
		break;
	      end = arg + 1;
	      goto do_k;
	    }
	    else
	      end = arg + 1;
	  break;

	  case 'k':
	    end = arg + 1;
	    switch (*end | 0x20)
	    {
	      case 'c': colour = &option.cmd_col; break;
	      case 'r': colour = &option.rec_col; break;
	      case 'p': colour = &option.drv_col;
			lastopt = 'k';
			break;
	      default:	opt = &option.nocolour; break;
	    }
	    if (opt)
	      break;
	    ++end;
	  do_k:
	    if (*end == ',')
	      break;
	    if (!isxdigit( *end ))
	    {
	      printf( "CMDkey: expecting hexadecimal digit for -k%c.\n",
		      (end[-1] == ',') ? 'p' : end[-1] | 0x20 );
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
#ifndef NT4
	    len = GetModuleFileName( NULL, cmdkey + 2, sizeof(cmdkey) - 3 );
	    strlwr( cmdkey + 2 );
	    cmdkey[0] = '&';
	    cmdkey[1] = cmdkey[2+len] = '"';
	    cmdkey[len += 3] = '\0';
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
	      RegQueryValueEx( key, AUTORUN, NULL, &type, opt, &exist );
	      if (!strstr( opt, cmdkey + 1 ))
	      {
		strcpy( opt + --exist, cmdkey );
		RegSetValueEx( key, AUTORUN, 0, type, opt, exist + len );
	      }
	    }
	    else
	    {
	      RegSetValueEx( key, AUTORUN, 0, REG_SZ, cmdkey + 1, len );
	    }
	    RegCloseKey( key );
	    free( opt );
	    opt = NULL;
#else
	    active = FALSE;
#endif
	    update = TRUE;
	  break;

	  case 'u':
	    if (*arg == 'U')
	      root = HKEY_LOCAL_MACHINE;
#ifndef NT4
	    // Remove CMDkey from CMD.EXE's AutoRun setting.
	    len = GetModuleFileName( NULL, cmdkey + 1, sizeof(cmdkey) - 2 );
	    strlwr( cmdkey + 1 );
	    cmdkey[0] = cmdkey[1+len] = '"';
	    cmdkey[len += 2] = '\0';
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
	      RegQueryValueEx( key, AUTORUN, NULL, &type, opt, &exist );
	      cmdpos = strstr( opt, cmdkey );
	      if (cmdpos)
	      {
		if (cmdpos == opt && exist == len + 1)
		  RegDeleteValue( key, AUTORUN );
		else
		{
		  if (cmdpos > opt && cmdpos[-1] == '&')
		    --cmdpos, ++len;
		  else if (cmdpos[len] == '&')
		    ++len;
		  memcpy( cmdpos, cmdpos + len, exist - len );
		  RegSetValueEx( key, AUTORUN, 0, type, opt, exist - len );
		}
	      }
	      free( opt );
	      opt = NULL;
	    }
	    RegCloseKey( key );
	    active = TRUE;
#endif
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
#ifdef NT4
      fname = argv[j];
#else
      strcpy( fname, argv[j] );
#endif
    }
  }
  if (update)
  {
#ifdef NT4
    if (*fname)
      GetFullPathName( fname, sizeof(cfgname), cfgname, NULL );
#else
    if (*cfgname)
      GetFullPathName( cfgname, sizeof(cfgname), cfgname, NULL );
    else if (!installed)
    {
      j = GetModuleFileName( NULL, cfgname, sizeof(cfgname) );
      arg = NULL;
      if (j > 4)
      {
	arg = cfgname + j - 4;
	if (stricmp( arg, ".exe" ) == 0)
	{
	  strcpy( arg, ".cfg" );
	  if (GetFileAttributes( cfgname ) == ~0)
	    arg = NULL;
	}
	else
	  arg = NULL;
      }
      if (!arg)
	*cfgname = 0;
    }
#endif

    RegCreateKeyEx( root, REGKEY, 0, "", REG_OPTION_NON_VOLATILE,
		    KEY_ALL_ACCESS, NULL, &key, &exist );
    RegSetValueEx( key, "Options", 0, REG_BINARY, (LPBYTE)&option,
		   sizeof(option) );
    RegSetValueEx( key, "Cmdfile", 0, REG_SZ, cfgname, strlen( cfgname ) + 1 );
    RegCloseKey( key );
  }

  if (!active)
  {
#ifndef NT4
    pinfo.hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE,
				  pinfo.dwProcessId );
    typedef HANDLE (__stdcall *func)( DWORD, BOOL, DWORD );
    func OpenThread = (func)GetProcAddress( GetModuleHandle( "KERNEL32.dll" ),
							     "OpenThread" );
    pinfo.hThread = OpenThread( THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
				THREAD_SET_CONTEXT, FALSE, pinfo.dwThreadId );
    SuspendThread( pinfo.hThread );
    Inject( &pinfo );
    CloseHandle( pinfo.hThread );
    CloseHandle( pinfo.hProcess );
#else
    STARTUPINFO sinfo;
    if (GetEnvironmentVariable( "ComSpec", cmdkey, sizeof(cmdkey) ) == 0)
      strcpy( cmdkey, "CMD.EXE" );
    ZeroMemory( &sinfo, sizeof(sinfo) );
    sinfo.cb = sizeof(sinfo);
    if (CreateProcess( NULL, cmdkey, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
		       NULL, &sinfo, &pinfo ))
    {
      Inject( &pinfo );
      WaitForSingleObject( pinfo.hProcess, INFINITE );
    }
  }
  else if (*fname)
  {
    strcpy( cmdname, fname );
#endif
  }

  return 0;
}


// Display the current status of CMDkey.
void status( void )
{
  char buf[4];
  char name[MAX_PATH+2];

  if (option.histsize)
    itoa( option.histsize, buf, 10 );
  else
    strcpy( buf, "all" );

  if (*cfgname)
    sprintf( name, "\"%s\"", cfgname );
  else
    strcpy( name, "none" );

  printf( "\n"
	  "* %s mode is default.\n"
	  "* Cursor sizes: insert = %d%%, overwrite = %d%%.\n"
	  "* Backslash appending is %sabled.\n"
	  "* Empty history search %s.\n"
	  "* Auto-recall is %sabled.\n"
	  "* Translation is %sabled.\n"
	  "* Error bell is %sabled.\n"
	  "* Ignore character is '%c'.\n"
	  "* Minimum history line length is %d.\n"
	  "* History will remember %s lines.\n"
	  "* Default configuration file: %s.\n"
	  "* CMDkey is %sabled.\n",
	  (option.overwrite) ? "Overwrite" : "Insert",
	  option.cursor_size[0], option.cursor_size[1],
	  (option.no_slash) ? "dis" : "en",
	  (option.empty_hist)? "moves cursor to end" : "leaves cursor at start",
	  (option.auto_recall) ? "en" : "dis",
	  (option.disable_macro) ? "dis" : "en",
	  (option.silent) ? "dis" : "en",
	  option.ignore_char,
	  option.min_length,
	  buf,
	  name,
	  (is_enabled) ? "en" : "dis"
	);
}


#ifndef NT4

// Search each process in the snapshot for id.
BOOL find_proc_id( HANDLE snap, DWORD id, LPPROCESSENTRY32 pe )
{
  BOOL fOk;

  pe->dwSize = sizeof(PROCESSENTRY32);
  for (fOk = Process32First( snap, pe ); fOk; fOk = Process32Next( snap, pe ))
    if (pe->th32ProcessID == id)
      break;

  return fOk;
}


// Obtain the process and thread identifiers of the parent process.
DWORD GetParentProcessInfo( LPPROCESS_INFORMATION pInfo )
{
  HANDLE hModuleSnap = NULL;
  PROCESSENTRY32 pe;
  THREADENTRY32  te;
  DWORD  id = GetCurrentProcessId();
  BOOL	 fOk;

  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD,
					  id );

  if (hModuleSnap == (HANDLE)-1)
  {
    puts( "CMDkey: unable to obtain process snapshot." );
    exit( 1 );
  }

  find_proc_id( hModuleSnap, id, &pe );
  find_proc_id( hModuleSnap, pe.th32ParentProcessID, &pe );

  te.dwSize = sizeof(te);
  for (fOk = Thread32First( hModuleSnap, &te ); fOk;
       fOk = Thread32Next( hModuleSnap, &te ))
    if (te.th32OwnerProcessID == pe.th32ProcessID)
      break;

  CloseHandle( hModuleSnap );

  if (!fOk)
  {
    puts( "CMDkey: could not obtain parent process." );
    exit( 1 );
  }

  pInfo->dwThreadId  = te.th32ThreadID;
  pInfo->dwProcessId = pe.th32ProcessID;

  return pe.th32ProcessID;
}


// Determine if CMDkey is already installed in the parent.
BOOL IsInstalled( DWORD id )
{
  HANDLE	hModuleSnap;
  MODULEENTRY32 me;
  BOOL		fOk;

  // Take a snapshot of all modules in the current process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, id );

  if (hModuleSnap == (HANDLE)-1)
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
      break;
  }
  CloseHandle( hModuleSnap );

  return fOk;
}

#endif


struct InjectData
{
  DWORD retaddr;		// original EIP to return to
  DWORD dlladdr;		// address of DLL filename
  DWORD funaddr;		// address of LoadLibraryA
  char	code[27];		// the actual code to load the library
  char	dllname[MAX_PATH];	// DLL filename
};

static struct InjectData inj = { 0, 0, 0, {
  0x50, 			// push eax
  0x53, 			// push ebx
  0x51, 			// push ecx
  0x52, 			// push edx
  0x56, 			// push esi
  0x57, 			// push edi
  0x55, 			// push ebp
  0x9c, 			// pushfd
  0xff, 0x74, 0x24, 0x24,	// push [esp + 8]
  0xff, 0x54, 0x24, 0x2c,	// call [esp + c]
  0x9d, 			// popfd
  0x5d, 			// pop	ebp
  0x5f, 			// pop	edi
  0x5e, 			// pop	esi
  0x5a, 			// pop	edx
  0x59, 			// pop	ecx
  0x5b, 			// pop	ebx
  0x58, 			// pop	eax
  0xc2, 0x08, 0x00		// ret	8
}, { 0 } };


// Inject code into the target process to load our DLL.  The target thread
// should be suspended on entry; it is restarted on exit.
void Inject( LPPROCESS_INFORMATION pinfo )
{
  CONTEXT context;
  char*   name;
  char*   path;
  DWORD   size;

  context.ContextFlags = CONTEXT_FULL;
  GetThreadContext( pinfo->hThread, &context );

  GetModuleFileNameA( NULL, inj.dllname, sizeof(inj.dllname) );
  for (name = path = inj.dllname; *path; ++path)
    if (*path == '\\')
      name = path + 1;
  lstrcpyA( name, "edit.dll" );

  size = (sizeof(inj)-sizeof(inj.dllname) + lstrlenA(inj.dllname) + 1 + 3) & ~3;
  *(unsigned short*)(inj.code+sizeof(inj.code)-2) = (unsigned short)(size-4);

  context.Esp -= size;
  inj.funaddr = (DWORD)GetProcAddress( GetModuleHandle( "kernel32.dll" ),
							"LoadLibraryA" );
  inj.dlladdr = context.Esp + offsetof(struct InjectData,dllname);
  inj.retaddr = context.Eip;
  WriteProcessMemory( pinfo->hProcess, (void*)context.Esp, &inj, size, NULL );

  context.Eip = context.Esp + offsetof(struct InjectData,code);
  VirtualProtectEx( pinfo->hProcess, (void*)context.Eip, sizeof(inj.code),
		    PAGE_EXECUTE_READWRITE, &size );

  SetThreadContext( pinfo->hThread, &context );
  ResumeThread( pinfo->hThread );
}


void help( void )
{
  puts(
  "CMDkey "
#ifdef NT4
  "(NT) "
#endif
  "by Jason Hood <jadoxa@yahoo.com.au>.\n"
  "Version "PVERS" ("PDATE").  Freeware.\n"
  "http://cmdkey.adoxa.cjb.net/\n"
  "\n"
  "Provide enhanced command line editing for CMD.EXE.\n"
  "\n"
  "cmdkey [-begkortz] [-c[INS][,OVR]] [-h[HIST]] [-lLEN] [-pCHAR] [filename] "
#ifdef NT4
  "[-i]\n"
#else
  "[-iu]\n"
#endif
  "       [-kcCMD] [-krREC] [-kp[DRV[,[SEP][,[DIR][,GT]]]]]\n"
  "\n"
  "    -b\t\tdisable backslash appending for completed directories\n"
  "    -c\t\tswap insert and overwrite cursors, or set their size\n"
  "    -e\t\tsearching history with an empty line will move cursor to end\n"
  "    -g\t\tsilent mode\n"
  "    -h\t\tremember the last HIST commands (0 will remember everything)\n"
  "    -k\t\tdisable colouring\n"
  "    -l\t\tminimum line length to remember\n"
  "    -o\t\tdefault overwrite mode\n"
  "    -p\t\tuse CHAR to disable translation for the current line\n"
  "    -r\t\tdefault auto-recall mode\n"
  "    -t\t\tdisable translation\n"
  "    -z\t\tdisable CMDkey\n"
  "    filename\tfile containing CMDkey commands and/or history lines\n"
  "\n"
  "    CMD\t\tcolour of the command line\n"
  "    REC\t\tcolour when recording a macro\n"
  "    DRV\t\tcolour of the prompt's drive letter and colon\n"
  "    SEP\t\tcolour of the prompt's directory separator\n"
  "    DIR\t\tcolour of the prompt's directory\n"
  "    GT\t\tcolour of the prompt's greater-than sign\n"
  "\n"
#ifdef NT4
  "    -i\t\tinstall (run new instance of CMD.EXE and make the current\n"
  "      \t\toptions the default)\n"
  "\n"
  "CMDkey with no arguments will display the status (it assumes it is running).\n"
#else
  "    -i\t\tinstall (add to CMD's AutoRun registry entry and make the\n"
  "      \t\tcurrent options the default)\n"
  "    -u\t\tuninstall (remove from AutoRun)\n"
  "\n"
  "CMDkey with no arguments will either install itself into the current CMD.EXE or\n"
  "display the status of the already running instance.\n"
#endif
  "When CMDkey is already running options -begkort will toggle the current state;\n"
  "prefix them with '+' to explicitly turn on (set behaviour indicated above) or\n"
  "with '-' to turn off (set default behaviour).  Eg: \"cmdkey -+b-g\" will disable\n"
  "backslash appending and enable the beep, irrespective of the current state.\n"
  "A colour is one or two hex digits; see CMD's COLOR help."
      );
}
