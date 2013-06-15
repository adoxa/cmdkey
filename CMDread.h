/*
  CMDread.h - Header file for CMDread.

  Jason Hood, 24 October, 2005.
*/


#ifdef _MSC_VER
#pragma warning (disable:4018) // ignore signed/unsigned mismatch
#pragma warning (disable:4267) // ignore conversion data loss (64-bit to 32)
#pragma warning (disable:4244) // ignore conversion data loss (64-bit ptr sub)
#endif

#ifndef UNICODE
#define UNICODE
#endif
#define _WIN32_WINNT 0x0500
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include <locale.h>
#include <io.h>
#include <fcntl.h>

#ifndef _O_U16TEXT
#define _O_U16TEXT 0x20000
#endif

#define WSZ(len) ((len) * sizeof(WCHAR))	// byte size of a wide string
#define lenof(a) (sizeof(a) / sizeof(*a))	// elements in a static array


typedef struct
{
  char	cursor_size[2]; 	// insert/overwrite cursor size
  char	overwrite;		// default insert/overwrite mode
  char	silent; 		// don't beep on errors?
  char	auto_recall;		// auto-recall commands
  char	disable_macro;		// disable macro & symbol translation
  char	disable_CMDread; 	// disable CMDread
  char	no_slash;		// don't append backslash on completed dirs
  char	empty_hist;		// move cursor to end on empty history search
  char	old_ignore_char;	// prefix character to disable translation
  UCHAR min_length;		// minimum line length to store in history
  UCHAR histsize;		// number of commands to store in history
  char	nocolour;		// disable colouring
  UCHAR cmd_col;		// command line colour
  UCHAR rec_col;		// recording colour
  UCHAR drv_col;		// prompt's drive colour
  UCHAR sep_col;		// prompt's directory separator colour
  UCHAR dir_col;		// prompt's directory colour
  UCHAR gt_col; 		// prompt's greater-than colour
  UCHAR base_col;		// prompt's base directory colour
  UCHAR sel_col;		// selection colour
  char	underscore;		// is underscore part of a word?
  WCHAR ignore_char;		// prefix character to disable translation
  WCHAR update_char;		// prefix character to update history line
} Option;


typedef struct
{
  int	version;
  char	enabled;		// is this instance active?
  WCHAR hstname[MAX_PATH];	// the history file
} Status;


#define REGKEY L"Software\\Adoxa\\CMDkey"
