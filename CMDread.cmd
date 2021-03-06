:: Having the exe in AutoRun causes a noticeable slow down in some batch files
:: (not due to anything it does, just the very act of loading it).  Running a
:: batch file has no such drawback, so use this to detect if the first argument
:: is "/C", in which case there's no need to load it.
@SetLocal EnableExtensions
:: Strip quotes, since FOR really doesn't like it when they're unbalanced.
@set "cmdline=%CMDCMDLINE:"=%"
:: This relies on %ComSpec% not having spaces.
@for /f "tokens=2" %%j in ("%cmdline%") do @set arg1=%%j
@if /i "%arg1%" NEQ "/c" "%~dpn0_%PROCESSOR_ARCHITECTURE%.exe" %*
