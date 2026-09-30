package heuristics

import (
	"bytes"
	"regexp"
)

// Finding is a single heuristic observation. Scores from all findings on an
// object are summed; reaching the configured threshold (default 100) makes
// the object malicious. A score of 100 on its own is therefore conclusive.
type Finding struct {
	Name        string `json:"name"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

// indicator matches lowercase content. It fires when any of Any matches (or
// Any is empty), all of All match, and Re (if set) matches.
type indicator struct {
	name  string
	score int
	desc  string
	any   []string
	all   []string
	re    *regexp.Regexp
	// near lists literal anchors; when set, re is only evaluated in a window
	// around each anchor occurrence instead of across the whole input.
	near []string
}

const (
	nearWindow  = 1024
	maxNearHits = 2000
)

func (in *indicator) match(lower []byte) bool {
	if len(in.any) > 0 {
		hit := false
		for _, s := range in.any {
			if bytes.Contains(lower, []byte(s)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, s := range in.all {
		if !bytes.Contains(lower, []byte(s)) {
			return false
		}
	}
	if in.re == nil {
		return true
	}
	if len(in.near) == 0 {
		return in.re.Match(lower)
	}
	for _, a := range in.near {
		anchor := []byte(a)
		for off, hits := 0, 0; hits < maxNearHits; hits++ {
			i := bytes.Index(lower[off:], anchor)
			if i < 0 {
				break
			}
			p := off + i
			if in.re.Match(lower[max(0, p-nearWindow):min(len(lower), p+len(anchor)+nearWindow)]) {
				return true
			}
			off = p + len(anchor)
		}
	}
	return false
}

func evalIndicators(set []indicator, lower []byte) []Finding {
	var out []Finding
	for i := range set {
		if set[i].match(lower) {
			out = append(out, Finding{Name: set[i].name, Score: set[i].score, Description: set[i].desc})
		}
	}
	return out
}

var re = regexp.MustCompile

// scriptIndicators apply to text content: PowerShell, JScript, VBScript,
// HTA, batch, shell, Python and PHP.
var scriptIndicators = []indicator{
	// --- PowerShell ---
	{name: "Heuristic.PowerShell.EncodedCommand", score: 60, desc: "PowerShell launched with a base64-encoded command",
		any: []string{"powershell", "pwsh"}, re: re(`\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand|ec)\s+["']?[a-z0-9+/=]{40,}`)},
	{name: "Heuristic.PowerShell.HiddenWindow", score: 25, desc: "PowerShell started with a hidden window",
		any: []string{"powershell", "pwsh"}, re: re(`-w(indowstyle|in|i)?\s+(hidden|1)\b`)},
	{name: "Heuristic.PowerShell.ExecutionPolicyBypass", score: 15, desc: "execution policy bypass",
		re: re(`-(ep|exec|executionpolicy)\s+(bypass|unrestricted)`), near: []string{"bypass", "unrestricted"}},
	{name: "Heuristic.PowerShell.DownloadCradle", score: 30, desc: "downloads remote content",
		any: []string{"downloadstring(", "downloadfile(", "downloaddata(", "invoke-webrequest", "start-bitstransfer", "net.webclient", "iwr ", "invoke-restmethod"}},
	{name: "Heuristic.PowerShell.DynamicExecution", score: 30, desc: "executes dynamically built code (IEX)",
		re: re(`(invoke-expression|\biex\s*\(\s*(new-object|\[|\(|\$)|\|\s*iex\b)`), near: []string{"invoke-expression", "iex"}},
	{name: "Heuristic.PowerShell.Base64Decode", score: 15, desc: "decodes base64 payloads",
		any: []string{"frombase64string"}},
	{name: "Heuristic.PowerShell.ReflectiveLoad", score: 35, desc: "loads .NET assemblies from memory",
		any: []string{"reflection.assembly]::load(", "[reflection.assembly]::load", "assembly]::load("}},
	{name: "Heuristic.PowerShell.ShellcodeLoader", score: 60, desc: "allocates executable memory via Win32 interop",
		any: []string{"virtualalloc"}, all: []string{"getdelegateforfunctionpointer"}},
	{name: "Heuristic.PowerShell.AMSIBypass", score: 100, desc: "attempts to disable AMSI",
		any: []string{"amsiinitfailed", "amsiscanbuffer", "amsiutils", "amsicontext"}},
	{name: "Heuristic.PowerShell.DefenderTamper", score: 60, desc: "disables Microsoft Defender",
		any: []string{"set-mppreference -disablerealtimemonitoring $true", "disablerealtimemonitoring 1", "add-mppreference -exclusionpath"}},

	// --- Windows script hosts / HTA / batch ---
	{name: "Heuristic.Script.WScriptShell", score: 30, desc: "uses WScript.Shell to run commands",
		any: []string{"wscript.shell"}},
	{name: "Heuristic.Script.ShellApplication", score: 25, desc: "uses Shell.Application ShellExecute",
		any: []string{"shell.application"}, all: []string{"shellexecute"}},
	{name: "Heuristic.Script.ActiveX", score: 10, desc: "instantiates ActiveX objects",
		any: []string{"activexobject", "createobject("}},
	{name: "Heuristic.Script.HTTPDownload", score: 25, desc: "downloads content with XMLHTTP/WinHTTP",
		any: []string{"msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "msxml2.serverxmlhttp"}},
	{name: "Heuristic.Script.WriteBinary", score: 30, desc: "writes binary data to disk via ADODB.Stream",
		any: []string{"adodb.stream"}, all: []string{"savetofile"}},
	{name: "Heuristic.Script.DropExecutable", score: 40, desc: "writes an executable or script file to disk",
		re: re(`savetofile\s*\(?[^\n]{0,200}\.(exe|dll|scr|com|pif|bat|cmd|ps1|vbs|js|hta)\b`), near: []string{"savetofile"}},
	{name: "Heuristic.Script.Obfuscation", score: 20, desc: "string-decoding obfuscation around eval",
		re: re(`eval\s*\(\s*(unescape|atob|string\.fromcharcode|decodeuricomponent|function\s*\(p,\s*a,\s*c,\s*k,\s*e)`), near: []string{"eval"}},
	{name: "Heuristic.Script.CharCodeObfuscation", score: 20, desc: "heavy character-code obfuscation",
		re: re(`((chrw?|string\.fromcharcode)\s*\(\s*\d+\s*\)[^\n]{0,20}){25,}`), near: []string{"fromcharcode", "chr"}},
	{name: "Heuristic.Script.LOLBin.Mshta", score: 30, desc: "invokes mshta",
		re: re(`mshta(\.exe)?\s+["']?(https?:|vbscript:|javascript:)`), near: []string{"mshta"}},
	{name: "Heuristic.Script.LOLBin.Regsvr32", score: 60, desc: "regsvr32 scriptlet execution (Squiblydoo)",
		re: re(`regsvr32(\.exe)?[^\n]*/i:\s*https?:`), near: []string{"regsvr32"}},
	{name: "Heuristic.Script.LOLBin.Certutil", score: 50, desc: "certutil used to download or decode payloads",
		re: re(`certutil(\.exe)?[^\n]*-(urlcache|decode|decodehex)`), near: []string{"certutil"}},
	{name: "Heuristic.Script.LOLBin.Bitsadmin", score: 40, desc: "bitsadmin used to download payloads",
		re: re(`bitsadmin(\.exe)?[^\n]*/transfer`), near: []string{"bitsadmin"}},
	{name: "Heuristic.Script.LOLBin.Rundll32", score: 30, desc: "rundll32 executing script or remote payload",
		re: re(`rundll32(\.exe)?[^\n]*(javascript:|mshtml,runhtmlapplication|\\\\\\\\[a-z0-9.]+\\|https?:)`), near: []string{"rundll32"}},
	{name: "Heuristic.Script.SpawnsPowerShell", score: 20, desc: "spawns PowerShell",
		any: []string{"powershell.exe", "powershell -", "powershell.exe -", "pwsh -"}},
	{name: "Heuristic.Script.Persistence.RunKey", score: 25, desc: "writes a registry Run key",
		re: re(`(reg(\.exe)?\s+add|regwrite|set-itemproperty|new-itemproperty)[^\n]*currentversion\\+run`), near: []string{"currentversion\\"}},
	{name: "Heuristic.Script.Persistence.ScheduledTask", score: 20, desc: "creates a scheduled task",
		any: []string{"schtasks /create", "schtasks.exe /create", "register-scheduledtask"}},
	{name: "Heuristic.Script.Ransomware.ShadowCopyDeletion", score: 70, desc: "deletes volume shadow copies",
		re: re(`(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|get-wmiobject\s+win32_shadowcopy[^\n]*delete)`), near: []string{"vssadmin", "shadowcopy"}},
	{name: "Heuristic.Script.Ransomware.RecoveryDisable", score: 50, desc: "deletes backups or disables Windows recovery",
		re: re(`(wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\s+/set\s+\{default\}\s+(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))`), near: []string{"wbadmin", "bcdedit"}},
	{name: "Heuristic.Script.AntiForensics.EventLogClear", score: 40, desc: "clears Windows event logs",
		re: re(`(wevtutil(\.exe)?\s+cl\b|clear-eventlog)`), near: []string{"wevtutil", "clear-eventlog"}},
	{name: "Heuristic.Script.AddUser", score: 25, desc: "creates local user accounts",
		re: re(`net(\.exe)?\s+user\s+\S+\s+\S+\s+/add`), near: []string{"/add"}},

	// --- Unix shell ---
	{name: "Heuristic.Shell.PipeToShell", score: 40, desc: "downloads and pipes content straight into a shell",
		re: re(`(curl|wget)[^\n|;]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b`), near: []string{"curl", "wget"}},
	{name: "Heuristic.Shell.Base64ToShell", score: 50, desc: "decodes base64 and executes it",
		re: re(`base64\s+(-d|--decode)[^\n]*\|\s*(ba|da|z)?sh\b`), near: []string{"base64"}},
	{name: "Heuristic.Shell.ReverseShell", score: 100, desc: "reverse shell",
		re: re(`(/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|\bnc(at)?\b[^\n]*\s-e\s*/bin/(ba)?sh|socat[^\n]*exec:[^\n]*(ba)?sh[^\n]*tcp|mkfifo[^\n]*\|\s*/bin/(ba)?sh[^\n]*\|\s*nc\b)`), near: []string{"/dev/tcp/", "/bin/sh", "/bin/bash", "socat"}},
	{name: "Heuristic.Shell.TmpExec", score: 25, desc: "makes files in world-writable dirs executable",
		re: re(`chmod\s+(\+x|[0-7]*7[0-7]{2})\s+/(tmp|var/tmp|dev/shm)/`), near: []string{"chmod"}},
	{name: "Heuristic.Shell.CronPersistence", score: 25, desc: "installs cron jobs that download content",
		re: re(`(crontab|/etc/cron)[^\n]*(curl|wget)\s[^\n]*https?://|(curl|wget)\s[^\n]*https?://[^\n]*(crontab|/etc/cron)`), near: []string{"crontab", "/etc/cron"}},
	{name: "Heuristic.Shell.SSHKeyPersistence", score: 30, desc: "appends to authorized_keys",
		re: re(`>>\s*[^\n]*\.ssh/authorized_keys`), near: []string{"authorized_keys"}},
	{name: "Heuristic.Shell.LdPreload", score: 50, desc: "modifies /etc/ld.so.preload (rootkit technique)",
		re: re(`>\s*/etc/ld\.so\.preload`), near: []string{"ld.so.preload"}},
	{name: "Heuristic.Shell.LogWipe", score: 25, desc: "wipes logs or shell history",
		re: re(`(rm\s+-rf?\s+/var/log|history\s+-c|unset\s+histfile|>\s*/var/log/(wtmp|btmp|lastlog|auth\.log))`), near: []string{"/var/log", "history", "histfile"}},
	{name: "Heuristic.Shell.SecurityDisable", score: 25, desc: "disables host security controls",
		re: re(`(setenforce\s+0|systemctl\s+(stop|disable)\s+(apparmor|firewalld|auditd)|ufw\s+disable|iptables\s+-f\b)`), near: []string{"setenforce", "systemctl", "ufw", "iptables"}},
	{name: "Heuristic.Shell.CompetitorKill", score: 60, desc: "kills rival cryptominers (common in cryptojacking droppers)",
		any: []string{"kinsing", "kdevtmpfsi", "pkill -f xmrig", "killall xmrig", "pkill -9 xmr"}},

	// --- Cryptominers ---
	{name: "Heuristic.Miner.Stratum", score: 60, desc: "cryptocurrency mining pool protocol",
		any: []string{"stratum+tcp://", "stratum+ssl://", "stratum2+tcp://"}},
	{name: "Heuristic.Miner.XMRig", score: 40, desc: "references XMRig miner",
		any: []string{"xmrig"}},

	// --- Python ---
	{name: "Heuristic.Python.ExecEncoded", score: 60, desc: "executes base64/zlib-encoded Python",
		re: re(`exec\s*\(\s*(__import__\(\s*['"](base64|zlib|marshal)['"]\s*\)|base64\.b64decode|zlib\.decompress|marshal\.loads)`), near: []string{"exec"}},
	{name: "Heuristic.Python.ReverseShell", score: 100, desc: "Python reverse shell",
		all: []string{"socket", "subprocess"}, re: re(`(os\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)|pty\.spawn\s*\(\s*["']/bin/(ba)?sh)`), near: []string{"dup2", "pty.spawn"}},

	// --- PHP web shells ---
	{name: "Heuristic.PHP.EvalEncoded", score: 60, desc: "evaluates encoded PHP",
		re: re(`(eval|assert)\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode|gzdecode)\s*\(`), near: []string{"eval", "assert"}},
	{name: "Heuristic.PHP.WebShell", score: 100, desc: "executes attacker-supplied request data",
		re: re(`(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|create_function|preg_replace\s*\(\s*['"][^'"]*/e['"])\s*\(\s*(@?\$_(get|post|request|cookie|server)|base64_decode\s*\(\s*\$_)`), near: []string{"$_", "base64_decode"}},
	{name: "Heuristic.PHP.KnownWebShell", score: 100, desc: "known web shell family",
		any: []string{"c99shell", "r57shell", "wso shell", "b374k", "filesman", "weevely"}, re: re(`<\?php|<\?=`)},

	// --- Credential theft ---
	{name: "Heuristic.Tool.Mimikatz", score: 100, desc: "Mimikatz credential dumping commands",
		any: []string{"sekurlsa::logonpasswords", "lsadump::sam", "lsadump::dcsync", "invoke-mimikatz", "sekurlsa::pth"}},
}

// binaryIndicators apply to raw bytes of native executables (lowercased).
var binaryIndicators = []indicator{
	{name: "Heuristic.Binary.Mimikatz", score: 100, desc: "Mimikatz credential dumper",
		any: []string{"sekurlsa::logonpasswords", "gentilkiwi", "mimikatz"}, all: []string{"sekurlsa"}},
	{name: "Heuristic.Binary.Ransomware.ShadowDelete", score: 60, desc: "deletes shadow copies / disables recovery",
		re: re(`(vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin\s+delete\s+catalog|recoveryenabled\s+no)`), near: []string{"vssadmin", "shadowcopy", "wbadmin", "recoveryenabled"}},
	{name: "Heuristic.Binary.Ransomware.Note", score: 40, desc: "contains ransom note text",
		re: re(`(your (files|documents|data)( and \w+)? (have been|are|were) (encrypted|locked)|decrypt(ion)? (tool|key|software)[^\n]{0,60}(bitcoin|btc|monero|tor browser))`), near: []string{"encrypted", "locked", "decrypt"}},
	{name: "Heuristic.Binary.Miner.Stratum", score: 60, desc: "cryptocurrency mining pool protocol",
		any: []string{"stratum+tcp://", "stratum+ssl://"}},
	{name: "Heuristic.Binary.Miner.XMRig", score: 40, desc: "embeds the XMRig miner",
		any: []string{"xmrig"}, all: []string{"randomx"}},
	{name: "Heuristic.Binary.Meterpreter", score: 100, desc: "Metasploit Meterpreter payload",
		any: []string{"metsrv.dll", "metsrv.x64.dll", "ext_server_stdapi"}},
	{name: "Heuristic.Binary.CobaltStrike", score: 100, desc: "Cobalt Strike beacon artefacts",
		any: []string{"beacon.dll", "beacon.x64.dll", "%s as %s\\%s: %d", "could not spawn %s: %d"}, all: []string{"reflectiveloader"}},
	{name: "Heuristic.Binary.ReflectiveLoader", score: 30, desc: "exports a reflective DLL loader",
		any: []string{"reflectiveloader"}},
	{name: "Heuristic.Binary.IoTBot", score: 60, desc: "Mirai/Gafgyt-style IoT botnet strings",
		any: []string{"/bin/busybox"}, re: re(`(/dev/watchdog|/dev/misc/watchdog)[\s\S]*(tftp|wget|/proc/net/tcp)|(gafgyt|bashlite|lolnogtfo|killer_kill|attack_udp|attack_tcp_syn|udpplain|hilix)`)},
	{name: "Heuristic.Binary.Rootkit.LdPreload", score: 40, desc: "manipulates /etc/ld.so.preload",
		any: []string{"/etc/ld.so.preload"}, all: []string{"readdir"}},
	{name: "Heuristic.Binary.CryptojackerDropper", score: 60, desc: "known cryptojacking malware family",
		any: []string{"kinsing", "kdevtmpfsi", "watchbog", "teamtnt"}},
	{name: "Heuristic.Binary.AMSIBypass", score: 40, desc: "patches AMSI",
		any: []string{"amsiscanbuffer"}, all: []string{"virtualprotect"}},
	{name: "Heuristic.Binary.ReverseShell", score: 50, desc: "spawns an interactive shell over a socket",
		re: re(`(/bin/sh -i|/bin/bash -i|cmd\.exe /k)`), all: []string{"connect"}, near: []string{"/bin/sh -i", "/bin/bash -i", "cmd.exe /k"}},
}

// vbaIndicators apply to decompressed VBA macro source.
var vbaIndicators = []indicator{
	{name: "Heuristic.Macro.AutoExec", score: 30, desc: "macro runs automatically when the document opens/closes",
		re: re(`\b(autoopen|auto_open|autoexec|autoclose|auto_close|document_open|documentopen|document_close|workbook_open|workbook_activate|workbook_beforeclose|app_documentopen|app_workbookopen|document_new|autonew)\b`)},
	{name: "Heuristic.Macro.Shell", score: 35, desc: "macro executes commands",
		re: re(`(\bshell\s*\(|\bshell\s+["\w]|wscript\.shell|shellexecute|\.run\s*\(?["\w]|\.exec\s*\(|win32_process|\.create\s*\()`)},
	{name: "Heuristic.Macro.Download", score: 35, desc: "macro downloads content",
		any: []string{"urldownloadtofile", "msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "msxml2.serverxmlhttp", "internetexplorer.application", "downloadfile", "downloadstring"}},
	{name: "Heuristic.Macro.WriteFile", score: 20, desc: "macro writes files to disk",
		any: []string{"adodb.stream", "savetofile", "put #", "binary access write", "scripting.filesystemobject"}},
	{name: "Heuristic.Macro.PowerShell", score: 40, desc: "macro launches PowerShell / script hosts",
		any: []string{"powershell", "pwsh", "mshta", "cscript", "wscript.exe", "cmd.exe", "cmd /c", "regsvr32", "rundll32", "certutil"}},
	{name: "Heuristic.Macro.Win32API", score: 30, desc: "macro declares Win32 API functions",
		re: re(`declare\s+(ptrsafe\s+)?(function|sub)\s+\w+\s+lib\s+"(kernel32|ntdll|user32|shell32|urlmon)`)},
	{name: "Heuristic.Macro.ShellcodeInjection", score: 70, desc: "macro allocates memory and runs shellcode",
		any: []string{"virtualalloc", "virtualallocex", "rtlmovememory", "createthread", "writeprocessmemory", "enumsystemlocales", "createtimerqueuetimer"}, all: []string{"lib \"kernel32"}},
	{name: "Heuristic.Macro.Obfuscation", score: 20, desc: "macro uses string obfuscation",
		re: re(`((chrw?\$?\s*\(\s*[\d&h]+\s*[\-+*/xor ]*\s*[\d&h]*\s*\)\s*[&+]\s*){15,}|strreverse\s*\(|callbyname\s*\()`)},
	{name: "Heuristic.Macro.Environment", score: 10, desc: "macro reads environment / temp paths",
		any: []string{"environ(", "environ$(", "%temp%", "%appdata%", "getspecialfolder"}},
	{name: "Heuristic.Macro.AntiAnalysis", score: 20, desc: "macro hides itself or disables security prompts",
		any: []string{"application.displayalerts = false", "accessvbom", "vbawarnings", "application.screenupdating = false"}, all: []string{"reg"}},
}

// pdfJSIndicators apply to JavaScript found in PDF streams.
var pdfJSIndicators = []indicator{
	{name: "Heuristic.PDF.JS.HeapSpray", score: 60, desc: "heap spray pattern",
		re: re(`(%u0c0c%u0c0c|%u9090%u9090|%u0a0a%u0a0a|\\x0c\\x0c\\x0c\\x0c|unescape\s*\(\s*["']%u[0-9a-f]{4}%u)`)},
	{name: "Heuristic.PDF.JS.KnownExploit", score: 80, desc: "calls an API with known Acrobat exploits",
		any: []string{"util.printf", "collab.geticon", "collab.collectemailinfo", "spell.customdictionaryopen", "media.newplayer", "getannots", "doc.printseps"}},
	{name: "Heuristic.PDF.JS.Eval", score: 20, desc: "evaluates dynamically built code",
		re: re(`eval\s*\(|unescape\s*\(|string\.fromcharcode`)},
	{name: "Heuristic.PDF.JS.Export", score: 30, desc: "exports embedded files or launches URLs",
		any: []string{"exportdataobject", "app.launchurl", "this.submitform"}},
}
