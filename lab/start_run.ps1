# Start the capture matrix DETACHED (hidden, survives closing the terminal / VS Code / this session).
# Re-running this script resumes a stopped run; a run that is already going refuses to start twice.
#
#   powershell -ExecutionPolicy Bypass -File lab\start_run.ps1            # full matrix (default)
#   powershell -ExecutionPolicy Bypass -File lab\start_run.ps1 -Mode mini # mini matrix (data\pcaps_mini)
#
# Output goes to lab\run.log. The PID of the run is written to lab\run.pid.
# While the run is alive a second hidden process asks Windows not to go to sleep (it does not change any power
# setting and exits when the run ends). Keep the laptop plugged in; closing the lid can still sleep it.
param([ValidateSet("full", "mini", "rep")][string]$Mode = "full")

$root = Split-Path -Parent $PSScriptRoot
$bash = "C:\Program Files\Git\bin\bash.exe"
if (-not (Test-Path $bash)) { throw "Git Bash not found at $bash" }

$wrapper = ($root -replace '\\', '/') + "/lab/run_detached.sh"
$run = Start-Process -FilePath $bash -ArgumentList @("-l", $wrapper, "--$Mode") -WorkingDirectory $root `
    -WindowStyle Hidden -PassThru
$run.Id | Out-File -Encoding ascii (Join-Path $root "lab\run.pid")

$keepAwake = @"
Add-Type -Namespace Win32 -Name Power -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint f);'
while (Get-Process -Id $($run.Id) -ErrorAction SilentlyContinue) {
    [void][Win32.Power]::SetThreadExecutionState(0x80000001)   # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    Start-Sleep -Seconds 30
}
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($keepAwake))
$ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
Start-Process -FilePath $ps -ArgumentList @("-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", $encoded) `
    -WindowStyle Hidden | Out-Null

"started $Mode run, PID $($run.Id); log: lab\run.log"
