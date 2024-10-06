# HexaneC2
## Overview:
Compilation of publicly available resources with minimal UI/UX features. A good portion of the code is derived from https://github.com/HavocFramework/Havoc.

The idea is to lay the groundwork for custom implementations and experiment with new features later on. This is not a production-ready C2 and I do not recommend using it in any real environments. 

There are plenty of IOCs that are intrinsic to the methods applied (if you know them, you can change it) and network communication is completely naked at the moment.
Not many EDRs (that I know of) have the capabilities of finding these indicators but an experienced blue team lead may find it. :^)

## TODO:
### Priorities:
(implant)
- testing implant P2P communication/ fixing protocol
- testing COFF loader
- re-implement generic thread stack spoofing/ sleepobf
- initial callback: get ETW-TI/kernel event options
- redirector rotation 
- client request header configuration and metadata 
- hot-swap configs (sleep/redirectors)
- implement COFF data cache
- write documentation

### C2 infrastructure:
#### Redirectors:
- re-implement http listener
- automation of infraC2
- protocol support (do not break)
- access control/ filtering
- forwarding through reverse proxy (nginx)
- (optional) "LetsEncrypt"
- (optional) multiple egress profiles

#### C2 Server:
- SSH connection
- save states db
- staging

### Wish-List:
- server response header configuration
- forking non-C2 traffic to webpage (filtering)
- implement dll manual mapping: https://github.com/bats3c/DarkLoadLibrary
- implement indirect syscalls/proxying through kernbase/kern32
- server logging
