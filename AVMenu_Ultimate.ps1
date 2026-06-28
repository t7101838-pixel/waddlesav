# ============================================================
#   ULTIMATE ANTIVIRUS v4.0 - AVMenu_Ultimate.ps1
#   Layers: Hash DB, VirusTotal, Heuristics, Content Scan,
#           Entropy, PE Analysis, YARA-style Rules,
#           MalwareBazaar + Multi-Feed Auto-Update,
#           Registry Scan, Network Monitor, DNS Monitor,
#           Behavior Monitor, Memory Scanner, Process Scanner,
#           Real-Time Watcher, Sandbox Launch, Scheduled Scans,
#           Quarantine Mgr, Whitelist Mgr, HTML Report,
#           Auto-Update Script, ML-style Threat Scoring
# ============================================================

# --- Self-exclusion ---
$ScriptHash = (Get-FileHash -Algorithm SHA256 -Path $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue).Hash

# --- Admin check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "[WARNING] Not running as Administrator. Some features limited." -ForegroundColor Yellow
    Start-Sleep 2
}

# ============================================================
#   PATHS
# ============================================================
$AVRoot           = "$HOME\Documents\UltimateAV"
$LogFile          = "$AVRoot\AV_Log.txt"
$QuarantineFolder = "$AVRoot\Quarantine"
$FavoritesFile    = "$AVRoot\Favorites.txt"
$ConfigFile       = "$AVRoot\Config.json"
$WhitelistFile    = "$AVRoot\Whitelist.txt"
$HashDBFile       = "$AVRoot\HashDB.txt"
$BadIPFile        = "$AVRoot\BadIPs.txt"
$BadURLFile       = "$AVRoot\BadURLs.txt"
$YaraRulesFile    = "$AVRoot\YaraRules.txt"
$ReportFolder     = "$AVRoot\Reports"
$ScanHistoryFile  = "$AVRoot\ScanHistory.json"
$Version          = "4.0"
$GitHubRaw        = "https://raw.githubusercontent.com/YourRepo/UltimateAV/main/AVMenu_Ultimate.ps1"

foreach ($p in @($AVRoot,$QuarantineFolder,$ReportFolder)) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
foreach ($p in @($FavoritesFile,$WhitelistFile,$HashDBFile,$BadIPFile,$BadURLFile,$YaraRulesFile)) {
    if (-not (Test-Path $p)) { New-Item -ItemType File -Path $p | Out-Null }
}
if (-not (Test-Path $ScanHistoryFile)) { "[]" | Set-Content $ScanHistoryFile }

# --- Auto-whitelist self ---
if ($ScriptHash) {
    $wl = Get-Content $WhitelistFile -ErrorAction SilentlyContinue
    if ($wl -notcontains $ScriptHash) { Add-Content $WhitelistFile $ScriptHash }
}

# ============================================================
#   GLOBAL STATE
# ============================================================
$global:VTApiKey    = ""
$global:Watcher     = $null
$global:HashDB      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$global:BadIPs      = [System.Collections.Generic.HashSet[string]]::new()
$global:BadURLs     = [System.Collections.Generic.HashSet[string]]::new()
$global:YaraRules   = @()
$global:ScanResults = @()
$global:DNSLog      = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

# Load config
if (Test-Path $ConfigFile) {
    try {
        $cfg = Get-Content $ConfigFile | ConvertFrom-Json
        if ($cfg.VTApiKey) { $global:VTApiKey = $cfg.VTApiKey }
    } catch {}
}

# ============================================================
#   LOAD THREAT DATABASES
# ============================================================
function Load-ThreatDB {
    $global:HashDB.Clear()
    $global:BadIPs.Clear()
    $global:BadURLs.Clear()

    if (Test-Path $HashDBFile) {
        Get-Content $HashDBFile | Where-Object { $_ -match '^[a-fA-F0-9]{64}$' } |
            ForEach-Object { [void]$global:HashDB.Add($_) }
    }
    if (Test-Path $BadIPFile) {
        Get-Content $BadIPFile | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } |
            ForEach-Object { [void]$global:BadIPs.Add($_.Trim()) }
    }
    if (Test-Path $BadURLFile) {
        Get-Content $BadURLFile | Where-Object { $_.Length -gt 3 } |
            ForEach-Object { [void]$global:BadURLs.Add($_.Trim().ToLower()) }
    }
    if (Test-Path $YaraRulesFile) {
        $global:YaraRules = Get-Content $YaraRulesFile | Where-Object { $_.Length -gt 0 }
    }
}
Load-ThreatDB

# ============================================================
#   COUNTERS
# ============================================================
$global:TotalFiles          = 0
$global:TotalBad            = 0
$global:TotalSuspicious     = 0
$global:TotalQuarantined    = 0
$global:TotalErrors         = 0
$global:TotalFoldersScanned = 0
$global:ScanStartTime       = Get-Date

# ============================================================
#   LOGGING
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content $LogFile $entry
}

# ============================================================
#   THREAT INTELLIGENCE AUTO-UPDATE (Multi-Feed)
# ============================================================
function Update-ThreatDB {
    Write-Host "`n=== Updating All Threat Intelligence Feeds ===" -ForegroundColor Cyan
    Write-Log "THREAT DB UPDATE STARTED" "INFO"

    $totalHashes = 0
    $totalIPs    = 0
    $totalURLs   = 0

    # --- 1. MalwareBazaar (SHA256 hashes) ---
    Write-Host "[1/6] MalwareBazaar hashes..." -ForegroundColor Yellow
    try {
        $r = Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method POST `
                 -Body "query=get_recent&selector=100" `
                 -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        if ($r.query_status -eq "ok") {
            $newH = $r.data | ForEach-Object { $_.sha256_hash }
            $existing = if (Test-Path $HashDBFile) { Get-Content $HashDBFile } else { @() }
            $combined = ($existing + $newH) | Sort-Object -Unique
            Set-Content $HashDBFile $combined
            foreach ($h in $newH) { [void]$global:HashDB.Add($h) }
            $totalHashes += $newH.Count
            Write-Host "   +$($newH.Count) hashes" -ForegroundColor Green
        }
    } catch { Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # --- 2. ThreatFox (IOCs - hashes + IPs) ---
    Write-Host "[2/6] ThreatFox IOCs..." -ForegroundColor Yellow
    try {
        $r = Invoke-RestMethod -Uri "https://threatfox-api.abuse.ch/api/v1/" -Method POST `
                 -Body '{"query":"get_iocs","days":1}' `
                 -ContentType "application/json" -ErrorAction Stop
        if ($r.query_status -eq "ok") {
            $hashes = $r.data | Where-Object { $_.ioc_type -eq "sha256_hash" } |
                      ForEach-Object { $_.ioc }
            $ips    = $r.data | Where-Object { $_.ioc_type -eq "ip:port" } |
                      ForEach-Object { ($_.ioc -split ":")[0] }
            $existing = if (Test-Path $HashDBFile) { Get-Content $HashDBFile } else { @() }
            $combined = ($existing + $hashes) | Sort-Object -Unique
            Set-Content $HashDBFile $combined
            foreach ($h in $hashes) { [void]$global:HashDB.Add($h) }
            $existingIPs = if (Test-Path $BadIPFile) { Get-Content $BadIPFile } else { @() }
            $combinedIPs = ($existingIPs + $ips) | Sort-Object -Unique
            Set-Content $BadIPFile $combinedIPs
            foreach ($ip in $ips) { [void]$global:BadIPs.Add($ip) }
            $totalHashes += $hashes.Count
            $totalIPs    += $ips.Count
            Write-Host "   +$($hashes.Count) hashes, +$($ips.Count) IPs" -ForegroundColor Green
        }
    } catch { Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # --- 3. Emerging Threats bad IPs ---
    Write-Host "[3/6] Emerging Threats IP blocklist..." -ForegroundColor Yellow
    try {
        $ipList = Invoke-RestMethod `
                      -Uri "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" `
                      -ErrorAction Stop
        $ips = $ipList -split "`n" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' } |
               ForEach-Object { $_.Trim() }
        $existingIPs = if (Test-Path $BadIPFile) { Get-Content $BadIPFile } else { @() }
        $combinedIPs = ($existingIPs + $ips) | Sort-Object -Unique
        Set-Content $BadIPFile $combinedIPs
        foreach ($ip in $ips) { [void]$global:BadIPs.Add($ip) }
        $totalIPs += $ips.Count
        Write-Host "   +$($ips.Count) IPs" -ForegroundColor Green
    } catch { Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # --- 4. Feodo Tracker (botnet C2 IPs) ---
    Write-Host "[4/6] Feodo Tracker botnet C2 IPs..." -ForegroundColor Yellow
    try {
        $r = Invoke-RestMethod -Uri "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" `
                 -ErrorAction Stop
        $ips = $r -split "`n" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+' -and $_ -notmatch '^#' } |
               ForEach-Object { $_.Trim() }
        $existingIPs = if (Test-Path $BadIPFile) { Get-Content $BadIPFile } else { @() }
        $combinedIPs = ($existingIPs + $ips) | Sort-Object -Unique
        Set-Content $BadIPFile $combinedIPs
        foreach ($ip in $ips) { [void]$global:BadIPs.Add($ip) }
        $totalIPs += $ips.Count
        Write-Host "   +$($ips.Count) C2 IPs" -ForegroundColor Green
    } catch { Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # --- 5. URLhaus malicious URLs ---
    Write-Host "[5/6] URLhaus malicious URLs..." -ForegroundColor Yellow
    try {
        $r = Invoke-RestMethod -Uri "https://urlhaus-api.abuse.ch/v1/urls/recent/" `
                 -Method POST -Body "limit=200" `
                 -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        if ($r.query_status -eq "ok") {
            $urls = $r.urls | Where-Object { $_.url_status -eq "online" } |
                    ForEach-Object { $_.url.ToLower() }
            $existingURLs = if (Test-Path $BadURLFile) { Get-Content $BadURLFile } else { @() }
            $combinedURLs = ($existingURLs + $urls) | Sort-Object -Unique
            Set-Content $BadURLFile $combinedURLs
            foreach ($u in $urls) { [void]$global:BadURLs.Add($u) }
            $totalURLs += $urls.Count
            Write-Host "   +$($urls.Count) malicious URLs" -ForegroundColor Green
        }
    } catch { Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # --- 6. Built-in YARA-style rules ---
    Write-Host "[6/6] Refreshing YARA-style rules..." -ForegroundColor Yellow
    $yaraRules = @(
        # Format: RULENAME|PATTERN
        "Encoded_PowerShell|powershell\s+-[Ee]nc\s+[A-Za-z0-9+/=]{20,}",
        "IEX_Invoke|IEX\s*\(|Invoke-Expression\s*\(",
        "WebClient_Download|Net\.WebClient.*Download(String|File|Data)",
        "AMSI_Bypass|amsiInitFailed|AmsiScanBuffer|amsi\.dll",
        "Mimikatz_String|mimikatz|sekurlsa|lsadump|dpapi",
        "Process_Injection|VirtualAlloc.*WriteProcessMemory|CreateRemoteThread",
        "Reflective_Load|System\.Reflection\.Assembly.*Load|ReflectivePEInjection",
        "Shellcode_Marker|\x4d\x5a\x90\x00|\xfc\x48\x83",
        "NetUser_Add|net\s+user\s+\S+\s+\S+\s+/add",
        "Scheduled_Task_Create|schtasks.*\/create.*\/sc",
        "Registry_Run_Key|reg\s+add.*CurrentVersion\\Run",
        "WScript_Shell|WScript\.Shell|Shell\.Application",
        "Certutil_Decode|certutil.*-decode|-urlcache.*-split",
        "BITS_Download|bitsadmin.*(\/transfer|\/download)",
        "Rundll32_Abuse|rundll32.*javascript:|rundll32.*vbscript:",
        "Base64_PE|TVqQAA|TVQAAA",
        "Hidden_Window|WindowStyle\s+Hidden|-W\s+Hidden|-WindowStyle\s+h",
        "Fork_Bomb|%0\|%0|:\(\)\{:\|:&\};:",
        "Ransomware_Ext|\.(locked|encrypted|crypted|crypt|enc|pays|wnry)$",
        "Suspicious_UserAgent|Mozilla.*MSIE 6|python-requests|curl\/[0-9]",
        "Token_Impersonation|ImpersonateLoggedOnUser|DuplicateTokenEx",
        "UAC_Bypass|fodhelper|eventvwr|sdclt|slui|computerdefaults"
    )
    Set-Content $YaraRulesFile ($yaraRules -join "`n")
    $global:YaraRules = $yaraRules
    Write-Host "   $($yaraRules.Count) rules loaded" -ForegroundColor Green

    Write-Host "`n=== Update Complete ===" -ForegroundColor Cyan
    Write-Host "Total hashes: $($global:HashDB.Count) | IPs: $($global:BadIPs.Count) | URLs: $($global:BadURLs.Count)" -ForegroundColor Green
    Write-Log "THREAT DB UPDATED Hashes:$($global:HashDB.Count) IPs:$($global:BadIPs.Count) URLs:$($global:BadURLs.Count)" "INFO"
    Pause
}

# ============================================================
#   VIRUSTOTAL
# ============================================================
function Get-VirusTotalResult {
    param([string]$Hash)
    if (-not $global:VTApiKey) { return $null }
    try {
        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" `
                 -Headers @{ "x-apikey" = $global:VTApiKey } -Method GET -ErrorAction Stop
        return [PSCustomObject]@{
            Malicious = $r.data.attributes.last_analysis_stats.malicious
            Suspicious= $r.data.attributes.last_analysis_stats.suspicious
            Total     = ($r.data.attributes.last_analysis_stats.PSObject.Properties |
                         Measure-Object -Property Value -Sum).Sum
            Name      = $r.data.attributes.meaningful_name
            Permalink = "https://www.virustotal.com/gui/file/$Hash"
        }
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            return [PSCustomObject]@{ Malicious=0; Suspicious=0; Total=0; Name=""; Permalink=$null }
        }
        return $null
    }
}

# ============================================================
#   PE FILE DEEP ANALYSIS
#   Parses Windows Portable Executable structure
# ============================================================
function Get-PEAnalysis {
    param([string]$FilePath)

    $result = [PSCustomObject]@{
        IsPE            = $false
        Is64Bit         = $false
        HasValidCert    = $false
        SuspiciousImports = @()
        SuspiciousSections = @()
        SectionCount    = 0
        ImportCount     = 0
        ThreatScore     = 0
        Flags           = @()
    }

    try {
        $bytes = [IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -lt 64) { return $result }

        # Check MZ header
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return $result }
        $result.IsPE = $true

        # Get PE offset
        $peOffset = [BitConverter]::ToInt32($bytes, 60)
        if ($peOffset + 4 -ge $bytes.Length) { return $result }

        # Check PE signature
        if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) { return $result }

        # Machine type (x64 = 0x8664)
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $result.Is64Bit = ($machine -eq 0x8664)

        # Section count
        $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $result.SectionCount = $sectionCount

        # Optional header size
        $optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $sectionTableOffset = $peOffset + 24 + $optHeaderSize

        # Suspicious section names (malware often uses these)
        $suspSectionNames = @(".upx0",".upx1",".upx2","UPX0","UPX1",".packed",".shrink",
                               ".themida",".winlicen",".ndata",".?",".!",".abc")

        for ($i = 0; $i -lt $sectionCount; $i++) {
            $secOffset = $sectionTableOffset + ($i * 40)
            if ($secOffset + 8 -ge $bytes.Length) { break }

            $nameBytes = $bytes[$secOffset..($secOffset+7)]
            $secName   = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)

            if ($suspSectionNames -contains $secName -or $secName -match '^\.[^a-zA-Z]') {
                $result.SuspiciousSections += $secName
                $result.ThreatScore += 15
                $result.Flags += "Suspicious section: $secName"
            }
        }

        # Check digital signature via PowerShell
        try {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
            $result.HasValidCert = ($sig.Status -eq "Valid")
            if ($sig.Status -eq "NotSigned") {
                $result.ThreatScore += 5
                $result.Flags += "Not digitally signed"
            } elseif ($sig.Status -eq "HashMismatch") {
                $result.ThreatScore += 40
                $result.Flags += "CERTIFICATE TAMPERED (hash mismatch)"
            }
        } catch {}

        # Check for known dangerous imports via strings
        $fileText = [System.Text.Encoding]::ASCII.GetString($bytes) + `
                    [System.Text.Encoding]::Unicode.GetString($bytes)

        $dangerousImports = @{
            "VirtualAllocEx"       = 20
            "WriteProcessMemory"   = 20
            "CreateRemoteThread"   = 25
            "NtUnmapViewOfSection" = 25
            "ZwUnmapViewOfSection" = 25
            "SetWindowsHookEx"     = 15
            "GetAsyncKeyState"     = 20
            "keybd_event"          = 15
            "IsDebuggerPresent"    = 10
            "CheckRemoteDebuggerPresent" = 10
            "NtQueryInformationProcess"  = 10
            "RegSetValueEx"        = 5
            "CreateService"        = 10
            "OpenSCManager"        = 10
            "CryptEncrypt"         = 8
            "WNetAddConnection"    = 8
            "InternetOpenUrl"      = 5
            "URLDownloadToFile"    = 15
            "ShellExecute"         = 5
            "WinExec"              = 15
            "CreateProcess"        = 5
        }

        foreach ($import in $dangerousImports.GetEnumerator()) {
            if ($fileText -match [regex]::Escape($import.Key)) {
                $result.SuspiciousImports += $import.Key
                $result.ThreatScore += $import.Value
                $result.ImportCount++
            }
        }

        # Combo bonuses (multiple dangerous APIs together = much more suspicious)
        if (($result.SuspiciousImports -contains "VirtualAllocEx") -and
            ($result.SuspiciousImports -contains "WriteProcessMemory") -and
            ($result.SuspiciousImports -contains "CreateRemoteThread")) {
            $result.ThreatScore += 40
            $result.Flags += "CLASSIC PROCESS INJECTOR API COMBO"
        }
        if (($result.SuspiciousImports -contains "GetAsyncKeyState") -and
            ($result.SuspiciousImports -contains "RegSetValueEx")) {
            $result.ThreatScore += 30
            $result.Flags += "POSSIBLE KEYLOGGER API COMBO"
        }
        if ($result.SuspiciousImports -contains "URLDownloadToFile") {
            $result.ThreatScore += 10
            $result.Flags += "Downloads files from internet"
        }

        if ($result.SuspiciousImports.Count -gt 0) {
            $result.Flags += "Dangerous imports: $($result.SuspiciousImports -join ', ')"
        }

    } catch {}

    return $result
}

# ============================================================
#   ML-STYLE THREAT SCORING
#   Combines all signals into a 0-100 threat score
# ============================================================
function Get-ThreatScore {
    param(
        [string]$FilePath,
        [double]$Entropy,
        [object]$PEResult,
        [int]$ContentHits,
        [int]$HeuristicHits,
        [int]$VTMalicious,
        [int]$VTTotal,
        [bool]$InHashDB
    )

    $score    = 0
    $reasons  = @()
    $ext      = [IO.Path]::GetExtension($FilePath).ToLower()
    $size     = try { (Get-Item $FilePath -ErrorAction Stop).Length } catch { 0 }
    $dir      = [IO.Path]::GetDirectoryName($FilePath).ToLower()

    # Hash DB match = very high confidence
    if ($InHashDB)                    { $score += 90; $reasons += "Known malware hash" }

    # VirusTotal results
    if ($VTTotal -gt 0) {
        $vtRatio = $VTMalicious / $VTTotal
        $score  += [Math]::Round($vtRatio * 80)
        if ($VTMalicious -gt 0) { $reasons += "VT: $VTMalicious/$VTTotal engines flagged" }
    }

    # PE analysis score
    if ($PEResult -and $PEResult.IsPE) {
        $score   += [Math]::Min($PEResult.ThreatScore, 60)
        $reasons += $PEResult.Flags
    }

    # Entropy
    if ($Entropy -gt 7.8)      { $score += 35; $reasons += "Critically high entropy ($Entropy)" }
    elseif ($Entropy -gt 7.2)  { $score += 20; $reasons += "High entropy ($Entropy)" }
    elseif ($Entropy -gt 6.8)  { $score += 8;  $reasons += "Elevated entropy ($Entropy)" }

    # Content/YARA hits
    if ($ContentHits -gt 5)    { $score += 40; $reasons += "$ContentHits malicious string patterns" }
    elseif ($ContentHits -gt 2){ $score += 25; $reasons += "$ContentHits malicious string patterns" }
    elseif ($ContentHits -gt 0){ $score += 12; $reasons += "$ContentHits malicious string pattern(s)" }

    # Heuristic hits
    $score += ($HeuristicHits * 10)

    # Location-based scoring
    if ($dir -match '\\temp\\|\\tmp\\')      { $score += 10; $reasons += "File in Temp folder" }
    if ($dir -match 'appdata\\roaming')       { $score += 8;  $reasons += "File in AppData Roaming" }
    if ($dir -match 'programdata')            { $score += 8;  $reasons += "File in ProgramData" }

    # Size anomalies for executables
    $highRiskExts = @(".exe",".dll",".scr",".com")
    if ($highRiskExts -contains $ext) {
        if ($size -lt 5120)          { $score += 10; $reasons += "Suspiciously small executable (<5KB)" }
        if ($size -gt 50MB)          { $score += 5;  $reasons += "Very large executable (>50MB)" }
    }

    # Cap at 100
    $score = [Math]::Min($score, 100)

    return [PSCustomObject]@{
        Score   = $score
        Level   = if ($score -ge 70) { "MALICIOUS" }
                  elseif ($score -ge 40) { "SUSPICIOUS" }
                  elseif ($score -ge 20) { "LOW RISK" }
                  else { "CLEAN" }
        Reasons = $reasons
    }
}

# ============================================================
#   YARA-STYLE RULE ENGINE
# ============================================================
function Test-YaraRules {
    param([string]$FilePath)

    $hits = @()
    $ext  = [IO.Path]::GetExtension($FilePath).ToLower()
    $scanExts = @(".exe",".dll",".bat",".cmd",".vbs",".ps1",".js",".hta",
                   ".wsf",".txt",".html",".xml",".doc",".docm",".xls",".xlsm")

    if ($scanExts -notcontains $ext -and $ext -notin @(".ps1",".bat",".vbs",".js")) {
        # For binary files, scan raw bytes as string
    }

    try {
        $content = [IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::ASCII)

        foreach ($rule in $global:YaraRules) {
            if ($rule -match '^(.+?)\|(.+)$') {
                $ruleName    = $matches[1]
                $rulePattern = $matches[2]
                try {
                    if ($content -match $rulePattern) {
                        $hits += $ruleName
                    }
                } catch {}
            }
        }
    } catch {}

    return $hits
}

# ============================================================
#   HEURISTICS
# ============================================================
function Test-Heuristic {
    param([string]$FilePath)
    $flags    = @()
    $ext      = [IO.Path]::GetExtension($FilePath).ToLower()
    $name     = [IO.Path]::GetFileName($FilePath).ToLower()
    $dir      = [IO.Path]::GetDirectoryName($FilePath).ToLower()
    $highRisk = @(".exe",".dll",".bat",".cmd",".vbs",".vbe",".js",".jse",
                   ".ps1",".psm1",".scr",".pif",".com",".hta",".jar",".msi",".wsf",".reg")

    if ($name -match '\.\w{2,4}\.\w{2,4}$' -and $highRisk -contains $ext) { $flags += "Double extension" }
    if ($dir -match 'temp|appdata|programdata' -and $highRisk -contains $ext) { $flags += "Executable in suspicious path" }
    if ($name.Length -gt 100) { $flags += "Unusually long filename" }
    if ($name -match '\.(docx?|xlsx?|pdf)\.\w+$') { $flags += "Script disguised as document" }
    if ($name -match '^[a-f0-9]{32,}(\.\w+)?$') { $flags += "Hash-like filename (possible dropper)" }
    try {
        $attrs = (Get-Item $FilePath -ErrorAction Stop).Attributes
        if ($attrs -band [IO.FileAttributes]::Hidden -and $highRisk -contains $ext) { $flags += "Hidden executable" }
        if ($attrs -band [IO.FileAttributes]::System  -and $highRisk -contains $ext) { $flags += "System-flagged executable" }
    } catch {}
    return $flags
}

# ============================================================
#   ENTROPY
# ============================================================
function Get-FileEntropy {
    param([string]$FilePath, [int]$MaxBytes = 131072)
    try {
        $bytes = [IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -gt $MaxBytes) { $bytes = $bytes[0..($MaxBytes-1)] }
        if ($bytes.Length -eq 0) { return 0.0 }
        $freq = @{}
        foreach ($b in $bytes) { $freq[$b]++ }
        $e = 0.0
        foreach ($c in $freq.Values) {
            $p = $c / $bytes.Length
            $e -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($e, 4)
    } catch { return 0.0 }
}

# ============================================================
#   WHITELIST
# ============================================================
function Test-Whitelisted {
    param([string]$Hash)
    $wl = Get-Content $WhitelistFile -ErrorAction SilentlyContinue
    return $wl -contains $Hash
}

# ============================================================
#   QUARANTINE
# ============================================================
function Invoke-Quarantine {
    param([string]$FilePath)
    $dest = Join-Path $QuarantineFolder "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$([IO.Path]::GetFileName($FilePath))"
    try {
        Move-Item -Path $FilePath -Destination $dest -Force
        $global:TotalQuarantined++
        Write-Host "  [QUARANTINED] -> $dest" -ForegroundColor DarkRed
        Write-Log "QUARANTINED $FilePath -> $dest" "QUARANTINE"
        return $true
    } catch {
        $global:TotalErrors++
        Write-Host "  [QUARANTINE FAILED] $($_.Exception.Message)" -ForegroundColor DarkRed
        Write-Log "QUARANTINE FAILED $FilePath $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ============================================================
#   SINGLE FILE SCAN (All layers)
# ============================================================
function Test-SingleFile {
    param([string]$FilePath, [switch]$Verbose)

    if (-not (Test-Path $FilePath -PathType Leaf)) { return }
    $global:TotalFiles++
    $ext = [IO.Path]::GetExtension($FilePath).ToLower()

    try {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction Stop).Hash

        if (Test-Whitelisted $hash) {
            if ($Verbose) { Write-Host "[WHITELIST]  $FilePath" -ForegroundColor DarkGray }
            return
        }

        # Gather all signals
        $inHashDB    = $global:HashDB.Contains($hash)
        $vtResult    = if ($global:VTApiKey -and -not $inHashDB) { Get-VirusTotalResult $hash } else { $null }
        $vtMalicious = if ($vtResult) { $vtResult.Malicious } else { 0 }
        $vtTotal     = if ($vtResult) { $vtResult.Total }     else { 0 }
        $heurFlags   = Test-Heuristic $FilePath
        $yaraHits    = Test-YaraRules $FilePath
        $entropy     = Get-FileEntropy $FilePath
        $peResult    = $null

        $highRisk = @(".exe",".dll",".scr",".com",".pif")
        if ($highRisk -contains $ext) {
            $peResult = Get-PEAnalysis $FilePath
        }

        $contentHits = $yaraHits.Count

        # ML-style scoring
        $scoring = Get-ThreatScore `
            -FilePath      $FilePath `
            -Entropy       $entropy `
            -PEResult      $peResult `
            -ContentHits   $contentHits `
            -HeuristicHits $heurFlags.Count `
            -VTMalicious   $vtMalicious `
            -VTTotal       $vtTotal `
            -InHashDB      $inHashDB

        # Store result for report
        $resultObj = [PSCustomObject]@{
            File        = $FilePath
            Hash        = $hash
            Score       = $scoring.Score
            Level       = $scoring.Level
            Reasons     = $scoring.Reasons -join "; "
            Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $global:ScanResults += $resultObj

        # Output based on threat level
        switch ($scoring.Level) {
            "MALICIOUS" {
                $global:TotalBad++
                Write-Host "[MALICIOUS]  [$($scoring.Score)/100] $FilePath" -ForegroundColor Red
                foreach ($r in $scoring.Reasons) { Write-Host "             $r" -ForegroundColor DarkRed }
                Write-Log "MALICIOUS Score:$($scoring.Score) $FilePath | $($scoring.Reasons -join ' | ')" "THREAT"
                Invoke-Quarantine $FilePath
            }
            "SUSPICIOUS" {
                $global:TotalSuspicious++
                Write-Host "[SUSPICIOUS] [$($scoring.Score)/100] $FilePath" -ForegroundColor Yellow
                foreach ($r in $scoring.Reasons) { Write-Host "             $r" -ForegroundColor DarkYellow }
                Write-Log "SUSPICIOUS Score:$($scoring.Score) $FilePath | $($scoring.Reasons -join ' | ')" "WARN"
            }
            "LOW RISK" {
                $global:TotalSuspicious++
                Write-Host "[LOW RISK]   [$($scoring.Score)/100] $FilePath" -ForegroundColor DarkYellow
                Write-Log "LOW RISK Score:$($scoring.Score) $FilePath" "WARN"
            }
            default {
                if ($Verbose) { Write-Host "[CLEAN]      [$($scoring.Score)/100] $FilePath" -ForegroundColor Green }
            }
        }

    } catch {
        $global:TotalErrors++
        Write-Host "[ERROR]      $FilePath" -ForegroundColor DarkGray
        Write-Log "ERROR $FilePath $($_.Exception.Message)" "ERROR"
    }
}

# ============================================================
#   MEMORY SCANNER
#   Scans memory of running processes for malicious patterns
# ============================================================
function Scan-ProcessMemory {
    Write-Host "`n=== Memory Scanner ===" -ForegroundColor Cyan
    Write-Host "Scanning process memory for malicious patterns..." -ForegroundColor Yellow
    Write-Log "MEMORY SCAN STARTED" "INFO"

    $maliciousPatterns = @(
        "mimikatz",
        "sekurlsa",
        "meterpreter",
        "ReflectivePE",
        "powershell -enc",
        "IEX(",
        "Invoke-Expression",
        "fromBase64String",
        "VirtualAlloc",
        "AmsiScanBuffer"
    )

    $procs    = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID }
    $total    = $procs.Count
    $flagged  = 0
    $i        = 0

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemReader {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_READABLE = 0x02 | 0x04 | 0x20 | 0x40;
}
"@ -ErrorAction SilentlyContinue

    foreach ($proc in $procs) {
        $i++
        Write-Host "`r  Scanning [$i/$total]: $($proc.Name.PadRight(20))" -NoNewline

        try {
            $handle = [MemReader]::OpenProcess(
                [MemReader]::PROCESS_VM_READ -bor [MemReader]::PROCESS_QUERY_INFORMATION,
                $false, $proc.Id)

            if ($handle -eq [IntPtr]::Zero) { continue }

            $address   = [IntPtr]::Zero
            $foundHits = @()

            # Walk memory regions
            $mbi = New-Object MemReader+MEMORY_BASIC_INFORMATION
            $mbiSize = [Runtime.InteropServices.Marshal]::SizeOf($mbi)

            while ([MemReader]::VirtualQueryEx($handle, $address, [ref]$mbi, [uint32]$mbiSize)) {
                $regionSize = $mbi.RegionSize.ToInt64()
                if ($regionSize -le 0 -or $regionSize -gt 10MB) {
                    $address = [IntPtr]($address.ToInt64() + [Math]::Max($regionSize, 4096))
                    if ($address.ToInt64() -le 0) { break }
                    continue
                }

                if ($mbi.State -eq [MemReader]::MEM_COMMIT -and
                    ($mbi.Protect -band [MemReader]::PAGE_READABLE) -ne 0) {

                    $buffer   = New-Object byte[] $regionSize
                    $bytesRead = 0
                    $ok = [MemReader]::ReadProcessMemory($handle, $mbi.BaseAddress, $buffer, $buffer.Length, [ref]$bytesRead)

                    if ($ok -and $bytesRead -gt 0) {
                        $memStr = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                        foreach ($pat in $maliciousPatterns) {
                            if ($memStr -match [regex]::Escape($pat)) {
                                $foundHits += $pat
                            }
                        }
                    }
                }

                $nextAddr = $address.ToInt64() + $regionSize
                if ($nextAddr -le $address.ToInt64()) { break }
                $address = [IntPtr]$nextAddr
            }

            [MemReader]::CloseHandle($handle) | Out-Null

            if ($foundHits.Count -gt 0) {
                $flagged++
                Write-Host ""
                Write-Host "[MEMORY HIT] $($proc.Name) (PID $($proc.Id))" -ForegroundColor Red
                Write-Host "             Patterns: $($foundHits | Sort-Object -Unique | Join-String -Separator ', ')" -ForegroundColor DarkRed
                Write-Log "MEMORY HIT $($proc.Name) PID:$($proc.Id) Patterns:$($foundHits -join ',')" "THREAT"

                $kill = Read-Host "  Kill $($proc.Name)? [Y/N]"
                if ($kill -eq "Y") {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "  Killed." -ForegroundColor DarkRed
                    Write-Log "PROCESS KILLED FROM MEMORY SCAN $($proc.Name) PID:$($proc.Id)" "ACTION"
                }
            }
        } catch { }
    }

    Write-Host ""
    Write-Host "`nMemory scan complete. Processes: $total | Flagged: $flagged" -ForegroundColor Cyan
    Write-Log "MEMORY SCAN COMPLETE Processes:$total Flagged:$flagged" "SUMMARY"
    Pause
}

# ============================================================
#   DNS MONITOR
#   Watches DNS queries against bad URL/domain list
# ============================================================
function Start-DNSMonitor {
    param([int]$DurationSeconds = 60)

    Write-Host "`n=== DNS Monitor ===" -ForegroundColor Cyan
    Write-Host "Monitoring DNS queries for $DurationSeconds seconds..." -ForegroundColor Yellow
    Write-Host "Checking against $($global:BadURLs.Count) known malicious domains." -ForegroundColor DarkGray
    Write-Log "DNS MONITOR STARTED Duration:${DurationSeconds}s" "INFO"

    $startTime  = Get-Date
    $endTime    = $startTime.AddSeconds($DurationSeconds)
    $alertCount = 0
    $seenDomains= [System.Collections.Generic.HashSet[string]]::new()

    # Enable DNS debug logging via ETW/netsh
    try {
        netsh trace start capture=yes tracefile="$env:TEMP\AVDNSTrace.etl" `
              provider=Microsoft-Windows-DNS-Client 2>$null | Out-Null
    } catch {}

    Write-Host "Monitoring active connections for suspicious domains..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C or wait for timer to stop." -ForegroundColor DarkGray
    Write-Host ""

    while ((Get-Date) -lt $endTime) {
        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds)
        Write-Host "`r  Time: ${elapsed}s/${DurationSeconds}s | Alerts: $alertCount   " -NoNewline

        try {
            # Get active TCP connections and resolve remote IPs to hostnames
            $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
            foreach ($conn in $conns) {
                $ip = $conn.RemoteAddress
                if ($seenDomains.Contains($ip)) { continue }
                [void]$seenDomains.Add($ip)

                # Check raw IP against bad IP list
                if ($global:BadIPs.Contains($ip)) {
                    $alertCount++
                    $pid2     = $conn.OwningProcess
                    $procName = try { (Get-Process -Id $pid2 -ErrorAction Stop).Name } catch { "Unknown" }
                    Write-Host ""
                    Write-Host "[DNS ALERT] Process '$procName' connected to blacklisted IP: $ip" -ForegroundColor Red
                    Write-Log "DNS ALERT $procName PID:$pid2 -> $ip (blacklisted)" "THREAT"
                }

                # Try reverse DNS and check domain
                try {
                    $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName.ToLower()
                    foreach ($badURL in $global:BadURLs) {
                        if ($hostname -match [regex]::Escape($badURL.Replace("http://","").Replace("https://","").Split("/")[0])) {
                            $alertCount++
                            $pid2     = $conn.OwningProcess
                            $procName = try { (Get-Process -Id $pid2 -ErrorAction Stop).Name } catch { "Unknown" }
                            Write-Host ""
                            Write-Host "[DNS ALERT] '$procName' connected to malicious domain: $hostname" -ForegroundColor Red
                            Write-Log "DNS ALERT $procName -> $hostname (malicious domain)" "THREAT"
                            break
                        }
                    }
                } catch {}
            }

            # Also check DNS cache for recently resolved bad domains
            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            foreach ($entry in $dnsCache) {
                $name = $entry.Entry.ToLower()
                foreach ($badURL in $global:BadURLs) {
                    $domain = $badURL.Replace("http://","").Replace("https://","").Split("/")[0].ToLower()
                    if ($domain.Length -gt 5 -and $name -match [regex]::Escape($domain)) {
                        if (-not $seenDomains.Contains("dns:$name")) {
                            [void]$seenDomains.Add("dns:$name")
                            $alertCount++
                            Write-Host ""
                            Write-Host "[DNS CACHE HIT] Malicious domain in DNS cache: $name" -ForegroundColor Red
                            Write-Log "DNS CACHE ALERT $name matched $domain" "THREAT"
                        }
                    }
                }
            }

        } catch {}

        Start-Sleep -Seconds 2
    }

    # Stop trace
    try { netsh trace stop 2>$null | Out-Null } catch {}

    Write-Host ""
    Write-Host "`nDNS monitor complete. Alerts: $alertCount" -ForegroundColor Cyan
    Write-Log "DNS MONITOR COMPLETE Alerts:$alertCount" "SUMMARY"
    Pause
}

# ============================================================
#   REGISTRY SCANNER
# ============================================================
function Scan-Registry {
    Write-Host "`n=== Registry Persistence Scanner ===" -ForegroundColor Cyan
    Write-Log "REGISTRY SCAN STARTED" "INFO"

    $registryKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKCU:\Environment",
        "HKLM:\System\CurrentControlSet\Services"
    )

    $suspiciousPatterns = @("powershell","cmd\.exe\s*/","wscript","cscript","mshta",
                             "regsvr32","rundll32","\.vbs","\.js","\.bat","\.ps1",
                             "temp\\","appdata\\roaming","frombase64","certutil","bitsadmin")
    $found   = 0
    $flagged = 0

    foreach ($key in $registryKeys) {
        if (-not (Test-Path $key)) { continue }
        Write-Host "`nChecking: $key" -ForegroundColor Yellow
        try {
            $values = Get-ItemProperty -Path $key -ErrorAction Stop
            $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $found++
                $name  = $_.Name
                $value = [string]$_.Value
                $isSusp = $false
                foreach ($pat in $suspiciousPatterns) {
                    if ($value -match $pat) { $isSusp = $true; break }
                }
                if ($isSusp) {
                    $flagged++
                    Write-Host "  [SUSPICIOUS] $name = $value" -ForegroundColor Red
                    Write-Log "REGISTRY SUSPICIOUS $key\$name = $value" "THREAT"
                    if ($value -match '"?([A-Za-z]:\\[^"]+\.(exe|dll|bat|ps1|vbs|js|cmd))"?') {
                        $refFile = $matches[1]
                        if (Test-Path $refFile) {
                            Write-Host "  Scanning referenced file..." -ForegroundColor Yellow
                            Test-SingleFile -FilePath $refFile -Verbose
                        }
                    }
                    $action = Read-Host "  Remove this entry? [Y/N]"
                    if ($action -eq "Y") {
                        try {
                            Remove-ItemProperty -Path $key -Name $name -Force
                            Write-Host "  Removed." -ForegroundColor DarkRed
                            Write-Log "REGISTRY REMOVED $key\$name" "ACTION"
                        } catch { Write-Host "  Could not remove: $($_.Exception.Message)" -ForegroundColor DarkRed }
                    }
                } else {
                    Write-Host "  [OK] $name"
                }
            }
        } catch { Write-Host "  Cannot read: $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    Write-Host "`nRegistry scan done. Checked: $found | Flagged: $flagged" -ForegroundColor Cyan
    Write-Log "REGISTRY SCAN COMPLETE Checked:$found Flagged:$flagged" "SUMMARY"
    Pause
}

# ============================================================
#   NETWORK MONITOR
# ============================================================
function Scan-NetworkConnections {
    Write-Host "`n=== Network Connection Monitor ===" -ForegroundColor Cyan
    Write-Log "NETWORK SCAN STARTED" "INFO"

    $badCount = 0
    $suspiciousPorts = @(1337,4444,4445,5555,6666,7777,8888,9999,31337,65535,1234,12345)

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop
        Write-Host "Active connections: $($connections.Count)" -ForegroundColor Yellow
        Write-Host ""

        foreach ($conn in $connections) {
            $ip       = $conn.RemoteAddress
            $port     = $conn.RemotePort
            $pid2     = $conn.OwningProcess
            $procName = try { (Get-Process -Id $pid2 -ErrorAction Stop).Name } catch { "Unknown" }
            $procPath = try { (Get-Process -Id $pid2 -ErrorAction Stop).Path } catch { "" }

            $isBad    = $global:BadIPs.Contains($ip)
            $isBadPort= $suspiciousPorts -contains $port

            if ($isBad -or $isBadPort) {
                $badCount++
                $reason = if ($isBad) { "Blacklisted IP" } else { "Suspicious port $port" }
                Write-Host "[SUSPICIOUS] $procName (PID $pid2) -> $ip`:$port | $reason" -ForegroundColor Red
                if ($procPath) { Write-Host "             $procPath" -ForegroundColor DarkRed }
                Write-Log "SUSPICIOUS CONNECTION $procName PID:$pid2 -> $ip`:$port $reason" "THREAT"
                $kill = Read-Host "  Kill $procName? [Y/N]"
                if ($kill -eq "Y") {
                    Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
                    Write-Host "  Killed." -ForegroundColor DarkRed
                    Write-Log "PROCESS KILLED $procName PID:$pid2" "ACTION"
                }
            } else {
                Write-Host "[OK]  $procName -> $ip`:$port"
            }
        }

        Write-Host "`n--- Listening Ports ---" -ForegroundColor Yellow
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
                $p = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).Name } catch { "Unknown" }
                Write-Host "  $p on port $($_.LocalPort)"
            }
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "`nNetwork scan done. Suspicious: $badCount" -ForegroundColor Cyan
    Write-Log "NETWORK SCAN COMPLETE Suspicious:$badCount" "SUMMARY"
    Pause
}

# ============================================================
#   BEHAVIOR MONITOR
# ============================================================
function Start-BehaviorMonitor {
    param([int]$DurationSeconds = 60)

    Write-Host "`n=== Behavior Monitor ===" -ForegroundColor Cyan
    Write-Host "Monitoring for $DurationSeconds seconds..." -ForegroundColor Yellow
    Write-Log "BEHAVIOR MONITOR STARTED Duration:${DurationSeconds}s" "INFO"

    $startTime  = Get-Date
    $endTime    = $startTime.AddSeconds($DurationSeconds)
    $alertCount = 0

    $suspiciousEventIDs = @{
        4688 = "New process created"
        4698 = "Scheduled task created"
        4702 = "Scheduled task updated"
        7045 = "New service installed"
        4720 = "User account created"
        4728 = "User added to privileged group"
        4732 = "User added to local admins"
        1102 = "Audit log CLEARED"
        4657 = "Registry value modified"
    }

    $suspiciousProcessNames = @("mimikatz","pwdump","fgdump","gsecdump","wce","procdump",
                                  "meterpreter","netcat","ncat","nc","psexec","mshta",
                                  "certutil","bitsadmin","cmstp","installutil","regasm")

    while ((Get-Date) -lt $endTime) {
        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds)
        Write-Host "`r  Time: ${elapsed}s/${DurationSeconds}s | Alerts: $alertCount   " -NoNewline

        try {
            foreach ($logName in @("Security","System")) {
                $events = Get-WinEvent -LogName $logName -MaxEvents 30 -ErrorAction SilentlyContinue |
                    Where-Object { $suspiciousEventIDs.ContainsKey($_.Id) -and $_.TimeCreated -gt $startTime }
                foreach ($evt in $events) {
                    $alertCount++
                    $desc = $suspiciousEventIDs[$evt.Id]
                    Write-Host ""
                    Write-Host "[BEHAVIOR] EventID $($evt.Id): $desc @ $($evt.TimeCreated)" -ForegroundColor Red
                    Write-Log "BEHAVIOR ALERT EventID:$($evt.Id) $desc" "THREAT"
                }
            }

            Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                if ($suspiciousProcessNames -contains $_.Name.ToLower()) {
                    $alertCount++
                    Write-Host ""
                    Write-Host "[BEHAVIOR] Suspicious process: $($_.Name) PID:$($_.Id)" -ForegroundColor Red
                    Write-Log "BEHAVIOR SUSPICIOUS PROCESS $($_.Name) PID:$($_.Id)" "THREAT"
                    $kill = Read-Host "  Kill $($_.Name)? [Y/N]"
                    if ($kill -eq "Y") { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
                }
            }
        } catch {}

        Start-Sleep -Seconds 3
    }

    Write-Host ""
    Write-Host "`nBehavior monitor done. Alerts: $alertCount" -ForegroundColor Cyan
    Write-Log "BEHAVIOR MONITOR COMPLETE Alerts:$alertCount" "SUMMARY"
    Pause
}

# ============================================================
#   PROCESS SCANNER
# ============================================================
function Scan-RunningProcesses {
    Write-Host "`n=== Process Scanner ===" -ForegroundColor Cyan
    Write-Log "PROCESS SCAN STARTED" "INFO"
    $procs = Get-Process | Where-Object { $_.Path -and (Test-Path $_.Path) }
    $total = $procs.Count; $bad = 0; $i = 0

    foreach ($proc in $procs) {
        $i++
        Write-Host "  [$i/$total] $($proc.Name.PadRight(25))" -NoNewline
        try {
            $hash  = (Get-FileHash -Algorithm SHA256 -Path $proc.Path -ErrorAction Stop).Hash
            $isBad = $false; $reason = ""

            if ($global:HashDB.Contains($hash)) { $isBad = $true; $reason = "Known bad hash" }
            if ($global:VTApiKey -and -not $isBad) {
                $vt = Get-VirusTotalResult $hash
                if ($vt -and $vt.Malicious -gt 3) { $isBad = $true; $reason = "VT $($vt.Malicious)/$($vt.Total)" }
            }
            if ($isBad) {
                $bad++
                Write-Host "[MALICIOUS - $reason]" -ForegroundColor Red
                Write-Log "MALICIOUS PROCESS $($proc.Name) PID:$($proc.Id) $reason" "THREAT"
                if ((Read-Host "  Kill $($proc.Name)? [Y/N]") -eq "Y") {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "  Killed." -ForegroundColor DarkRed
                }
            } else { Write-Host "[OK]" -ForegroundColor Green }
        } catch { Write-Host "[SKIP]" -ForegroundColor DarkGray }
    }

    Write-Host "`nProcesses: $total | Malicious: $bad" -ForegroundColor Cyan
    Write-Log "PROCESS SCAN COMPLETE Total:$total Malicious:$bad" "SUMMARY"
    Pause
}

# ============================================================
#   REAL-TIME WATCHER
# ============================================================
function Start-RealtimeWatcher {
    param([string]$WatchPath)
    if (-not (Test-Path $WatchPath)) { Write-Host "Path not found." -ForegroundColor Red; return }

    Write-Host "`nWatcher started: $WatchPath" -ForegroundColor Cyan
    Write-Log "WATCHER STARTED $WatchPath" "INFO"

    $global:Watcher = New-Object System.IO.FileSystemWatcher
    $global:Watcher.Path = $WatchPath
    $global:Watcher.Filter = "*.*"
    $global:Watcher.IncludeSubdirectories = $true
    $global:Watcher.EnableRaisingEvents = $true

    $action = {
        $path = $Event.SourceEventArgs.FullPath
        $type = $Event.SourceEventArgs.ChangeType
        Write-Host "`n[WATCHER] $type : $path" -ForegroundColor Magenta
        Add-Content $using:LogFile "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WATCHER] $type $path"
        Test-SingleFile -FilePath $path
    }

    $global:WECreated  = Register-ObjectEvent $global:Watcher "Created" -Action $action
    $global:WEModified = Register-ObjectEvent $global:Watcher "Changed" -Action $action

    Write-Host "ACTIVE - press any key to stop..." -ForegroundColor Green
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    Unregister-Event -SourceIdentifier $global:WECreated.Name  -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $global:WEModified.Name -ErrorAction SilentlyContinue
    $global:Watcher.EnableRaisingEvents = $false
    $global:Watcher.Dispose()
    Write-Host "Watcher stopped." -ForegroundColor DarkYellow
    Write-Log "WATCHER STOPPED $WatchPath" "INFO"
}

# ============================================================
#   SANDBOX LAUNCH
#   Runs suspicious file inside Windows Sandbox
# ============================================================
function Invoke-Sandbox {
    param([string]$FilePath)

    Write-Host "`n=== Sandbox Detonation ===" -ForegroundColor Cyan

    # Check if Windows Sandbox is available
    $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
    if (-not $sandboxFeature -or $sandboxFeature.State -ne "Enabled") {
        Write-Host "Windows Sandbox is not enabled." -ForegroundColor Yellow
        Write-Host "To enable: Settings -> Windows Features -> Windows Sandbox" -ForegroundColor DarkYellow
        Write-Host ""
        Write-Host "Alternatively, the file will be opened in an isolated PowerShell job." -ForegroundColor DarkGray

        $confirm = Read-Host "Run '$FilePath' in isolated monitoring mode? [Y/N]"
        if ($confirm -eq "Y") {
            Write-Host "Launching with monitoring..." -ForegroundColor Yellow
            $job = Start-Job -ScriptBlock {
                param($fp)
                try { & $fp } catch { $_.Exception.Message }
            } -ArgumentList $FilePath

            Start-Sleep -Seconds 5
            $result = Receive-Job $job -ErrorAction SilentlyContinue
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -ErrorAction SilentlyContinue

            Write-Host "Job output: $result" -ForegroundColor DarkGray
        }
        Pause
        return
    }

    # Create sandbox config file
    $sandboxConfig = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$([IO.Path]::GetDirectoryName($FilePath))</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd /c "$FilePath"</Command>
  </LogonCommand>
  <Networking>Disable</Networking>
</Configuration>
"@
    $configPath = "$env:TEMP\AV_Sandbox.wsb"
    Set-Content $configPath $sandboxConfig

    Write-Host "Launching Windows Sandbox with: $FilePath" -ForegroundColor Yellow
    Write-Host "Networking is DISABLED in sandbox." -ForegroundColor DarkGray
    Write-Host "Close the sandbox window when done." -ForegroundColor DarkGray
    Write-Log "SANDBOX LAUNCHED $FilePath" "INFO"

    Start-Process $configPath -Wait
    Remove-Item $configPath -Force -ErrorAction SilentlyContinue
    Write-Host "Sandbox closed." -ForegroundColor Green
    Pause
}

# ============================================================
#   HTML SCAN REPORT
# ============================================================
function Export-HTMLReport {
    $timestamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $reportPath = "$ReportFolder\ScanReport_$timestamp.html"
    $duration   = (Get-Date) - $global:ScanStartTime

    $threatRows    = ""
    $suspiciousRows= ""
    $cleanCount    = 0

    foreach ($r in $global:ScanResults) {
        $rowColor = switch ($r.Level) {
            "MALICIOUS"  { "#ff4444" }
            "SUSPICIOUS" { "#ffaa00" }
            "LOW RISK"   { "#ffdd00" }
            default      { "#44ff44" }
        }
        $row = "<tr style='background:$rowColor22'><td>$($r.Level)</td><td>$($r.Score)</td><td style='word-break:break-all'>$($r.File)</td><td style='word-break:break-all'>$($r.Reasons)</td><td>$($r.Timestamp)</td></tr>"
        if ($r.Level -eq "MALICIOUS" -or $r.Level -eq "SUSPICIOUS") { $threatRows += $row }
        else { $cleanCount++ }
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Ultimate AV Scan Report - $timestamp</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
  h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
  h2 { color: #79c0ff; margin-top: 30px; }
  .summary { display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; min-width: 140px; text-align: center; }
  .card .num { font-size: 2.5em; font-weight: bold; }
  .card .label { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
  .red   { color: #ff4444; }
  .yellow{ color: #ffaa00; }
  .green { color: #44ff44; }
  .blue  { color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.88em; }
  th { background: #21262d; padding: 10px; text-align: left; border: 1px solid #30363d; }
  td { padding: 8px 10px; border: 1px solid #21262d; vertical-align: top; }
  tr:hover td { background: #1c2128; }
  .badge { display:inline-block; padding: 2px 8px; border-radius: 4px; font-size:0.8em; font-weight:bold; }
  .badge-mal  { background:#ff444433; color:#ff4444; border:1px solid #ff4444; }
  .badge-susp { background:#ffaa0033; color:#ffaa00; border:1px solid #ffaa00; }
  .badge-low  { background:#ffdd0033; color:#ffdd00; border:1px solid #ffdd00; }
  .badge-clean{ background:#44ff4433; color:#44ff44; border:1px solid #44ff44; }
  .progress-bar { background:#21262d; border-radius:4px; height:8px; margin:8px 0; }
  .progress-fill{ height:8px; border-radius:4px; background: linear-gradient(90deg, #58a6ff, #ff4444); }
</style>
</head>
<body>
<h1>🛡️ Ultimate Antivirus v$Version — Scan Report</h1>
<p style='color:#8b949e'>Generated: $(Get-Date -Format 'dddd, MMMM dd yyyy HH:mm:ss') | Duration: $($duration.ToString('hh\:mm\:ss'))</p>

<div class='summary'>
  <div class='card'><div class='num blue'>$global:TotalFiles</div><div class='label'>Files Scanned</div></div>
  <div class='card'><div class='num red'>$global:TotalBad</div><div class='label'>Threats Found</div></div>
  <div class='card'><div class='num yellow'>$global:TotalSuspicious</div><div class='label'>Suspicious</div></div>
  <div class='card'><div class='num red'>$global:TotalQuarantined</div><div class='label'>Quarantined</div></div>
  <div class='card'><div class='num green'>$cleanCount</div><div class='label'>Clean Files</div></div>
  <div class='card'><div class='num blue'>$($global:HashDB.Count)</div><div class='label'>Hash DB Size</div></div>
  <div class='card'><div class='num blue'>$($global:BadIPs.Count)</div><div class='label'>Bad IPs Loaded</div></div>
</div>

<h2>🔴 Threats &amp; Suspicious Files</h2>
$(if ($threatRows) {
"<table><tr><th>Level</th><th>Score</th><th>File</th><th>Reasons</th><th>Time</th></tr>$threatRows</table>"
} else {
"<p class='green'>✅ No threats or suspicious files detected.</p>"
})

<h2>📊 Threat Score Distribution</h2>
<table>
  <tr><th>Score Range</th><th>Classification</th><th>Count</th></tr>
  <tr><td>70-100</td><td><span class='badge badge-mal'>MALICIOUS</span></td><td>$global:TotalBad</td></tr>
  <tr><td>40-69</td><td><span class='badge badge-susp'>SUSPICIOUS</span></td><td>$(($global:ScanResults | Where-Object {$_.Level -eq 'SUSPICIOUS'}).Count)</td></tr>
  <tr><td>20-39</td><td><span class='badge badge-low'>LOW RISK</span></td><td>$(($global:ScanResults | Where-Object {$_.Level -eq 'LOW RISK'}).Count)</td></tr>
  <tr><td>0-19</td><td><span class='badge badge-clean'>CLEAN</span></td><td>$cleanCount</td></tr>
</table>

<h2>ℹ️ Scan Configuration</h2>
<table>
  <tr><th>Setting</th><th>Value</th></tr>
  <tr><td>VirusTotal API</td><td>$(if ($global:VTApiKey) {'✅ Enabled'} else {'❌ Disabled'})</td></tr>
  <tr><td>Hash Database</td><td>$($global:HashDB.Count) hashes</td></tr>
  <tr><td>Bad IP Database</td><td>$($global:BadIPs.Count) IPs</td></tr>
  <tr><td>YARA Rules</td><td>$($global:YaraRules.Count) rules</td></tr>
  <tr><td>Folders Scanned</td><td>$global:TotalFoldersScanned</td></tr>
  <tr><td>Errors</td><td>$global:TotalErrors</td></tr>
</table>

<p style='color:#8b949e; margin-top:40px; font-size:0.8em'>Ultimate Antivirus v$Version | Report saved to $reportPath</p>
</body>
</html>
"@

    Set-Content $reportPath $html -Encoding UTF8
    Write-Host "`nHTML report saved: $reportPath" -ForegroundColor Green
    Write-Log "HTML REPORT EXPORTED $reportPath" "INFO"

    $open = Read-Host "Open report in browser? [Y/N]"
    if ($open -eq "Y") { Start-Process $reportPath }
}

# ============================================================
#   AUTO-UPDATE SCRIPT
# ============================================================
function Update-Script {
    Write-Host "`n=== Script Auto-Update ===" -ForegroundColor Cyan
    Write-Host "Checking for updates..." -ForegroundColor Yellow
    Write-Host "(Note: Point `$GitHubRaw to your own hosted script URL to use this)" -ForegroundColor DarkGray

    try {
        $latest = Invoke-RestMethod -Uri $GitHubRaw -ErrorAction Stop
        $verLine = $latest -split "`n" | Where-Object { $_ -match '\$Version\s*=' } | Select-Object -First 1
        if ($verLine -match '"([0-9.]+)"') {
            $latestVer = $matches[1]
            if ([version]$latestVer -gt [version]$Version) {
                Write-Host "New version available: v$latestVer (current: v$Version)" -ForegroundColor Green
                $confirm = Read-Host "Update now? [Y/N]"
                if ($confirm -eq "Y") {
                    $backupPath = "$AVRoot\AVMenu_Backup_v$Version.ps1"
                    Copy-Item $MyInvocation.MyCommand.Path $backupPath -Force
                    Set-Content $MyInvocation.MyCommand.Path $latest -Encoding UTF8
                    Write-Host "Updated! Backup saved to $backupPath" -ForegroundColor Green
                    Write-Host "Restart the script to use the new version." -ForegroundColor Yellow
                    Write-Log "SCRIPT UPDATED v$Version -> v$latestVer" "INFO"
                }
            } else {
                Write-Host "You are on the latest version (v$Version)." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "Could not check for updates. Set `$GitHubRaw to your update URL." -ForegroundColor DarkYellow
    }
    Pause
}

# ============================================================
#   SCHEDULED SCAN
# ============================================================
function Register-ScheduledScan {
    Write-Host "`n=== Scheduled Scan ===" -ForegroundColor Cyan
    $time = Read-Host "Run daily at what time? (e.g. 02:00)"
    try {
        $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                       -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        $trigger = New-ScheduledTaskTrigger -Daily -At $time
        $settings= New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun:$false
        Register-ScheduledTask -TaskName "UltimateAV_DailyScan" `
            -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
        Write-Host "Scheduled daily at $time" -ForegroundColor Green
        Write-Log "SCHEDULED TASK REGISTERED daily at $time" "INFO"
    } catch { Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red }
    Pause
}

function Remove-ScheduledScan {
    try {
        Unregister-ScheduledTask -TaskName "UltimateAV_DailyScan" -Confirm:$false
        Write-Host "Removed." -ForegroundColor Green
    } catch { Write-Host "Not found." -ForegroundColor DarkYellow }
    Pause
}

# ============================================================
#   SCAN SUMMARY
# ============================================================
function Show-Summary {
    $dur = (Get-Date) - $global:ScanStartTime
    Write-Host "`n==============================" -ForegroundColor Cyan
    Write-Host "         SCAN SUMMARY"
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "Folders scanned:   $global:TotalFoldersScanned"
    Write-Host "Files scanned:     $global:TotalFiles"
    Write-Host "Threats (70+):     $global:TotalBad"       -ForegroundColor $(if ($global:TotalBad -gt 0){"Red"} else {"Green"})
    Write-Host "Suspicious (40+):  $global:TotalSuspicious" -ForegroundColor $(if ($global:TotalSuspicious -gt 0){"Yellow"} else {"Green"})
    Write-Host "Quarantined:       $global:TotalQuarantined"
    Write-Host "Errors:            $global:TotalErrors"
    Write-Host "Time taken:        $($dur.ToString('hh\:mm\:ss'))"
    Write-Host "Hash DB:           $($global:HashDB.Count) hashes"
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Log "SCAN SUMMARY Files:$global:TotalFiles Threats:$global:TotalBad Suspicious:$global:TotalSuspicious Quarantined:$global:TotalQuarantined Time:$($dur.ToString('hh\:mm\:ss'))" "SUMMARY"

    $export = Read-Host "Export HTML report? [Y/N]"
    if ($export -eq "Y") { Export-HTMLReport }
}

# ============================================================
#   FOLDER SCAN ENGINE
# ============================================================
function Run-Scan {
    param([string[]]$Folders, [switch]$Verbose)

    $global:ScanStartTime = Get-Date
    $global:TotalFiles=$global:TotalBad=$global:TotalSuspicious=0
    $global:TotalQuarantined=$globa