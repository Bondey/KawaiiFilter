# KawaiiFilter
My all in one VM harden&monitor

## TODO

- R0 Malfind
- Filter R3 agent log info by R3 config
- WMI monitor and manipulate
- Network mini-filter
- Create Process with selected parent by IOCTL
- Fake registry content by R3 config
- Fake file content by R3 config
- Get more Info by PID using: stack trace, PEB, EPROCESS
- Add Driver IOCTL monitor

## Features

### Hidding process images by DKOM
**Some stuff need to be done before using this feature**

  1- **Disable PatchGuard, try [EfiGuard](https://github.com/Mattiwatti/EfiGuard), [UPGDSED](https://github.com/hfiref0x/UPGDSED) or [Shark](https://github.com/9176324/Shark).**

  2. **Enable testSigning: "bcdedit /set testsigning on"**

### Sysmon Like system monitoring
- Can monitor de wole system (not recomended)
- Can filter by PID, a new PID is monitored if:

  -- Is created by a monitored process

  -- Gets a new Remote Thread from a monitored process
  
  -- A Handle to the process is opened by a monitored Process

### ATM this Driver monitors
- Registry
- File System
- Image Load
- Thread creation
- New Proceses
- Open Process

# FAQ
Most of the code is thanks to the book "Windows kernel programming" from Pavel Yosifovich

¿Trying to read my code? sry...
![Image of devel](https://github.com/Bondey/KawaiiFilter/blob/master/misc/devel.jpg)
