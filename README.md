# filegate

Please produce **FileGate**. This is a CLI tool for Linux boxes that hosts an optional REST-API as system service (requires an API Key, generated through the CLI).

FileGate scans files and archives to detect malware. A file can be passed in, and FileGate must rapidly return a verdict of `safe` or `malicious`.  

FileGate must be highly capable of testing the file, and should update any used databases regularly. 
