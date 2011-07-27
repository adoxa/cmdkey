/*
  cmdkey.h - Header file for CMDkey.

  Jason Hood, 24 October, 2005.
*/


#define WIN32_LEAN_AND_MEAN
#include <windows.h>


typedef struct
{
  char	cursor_size[2]; 	// insert/overwrite cursor size
  char	overwrite;		// default insert/overwrite mode
  char	silent; 		// don't beep on errors?
  char	auto_recall;		// auto-recall commands
  char	disable_macro;		// disable macro & symbol translation
  char	disable_cmdkey; 	// disable CMDkey
  char	no_slash;		// don't append backslash on completed dirs
  char	empty_hist;		// move cursor to end on empty history search
  char	ignore_char;		// prefix character to disable translation
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
  char	underscore;		// is underscore part of a word?
} Option;


#define REGKEY "Software\\Adoxa\\CMDkey"
