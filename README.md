# HexaneC2
## Overview:
A compilation of publicly available resources with minimal UI/UX features. A good portion of the code is derived from https://github.com/HavocFramework/Havoc, taking inspiration from other popular frameworks as well.

This is meant to lay the groundwork for my custom implementations/ R&D rather than being a feature-rich user experience (it's unpolished). This is not a production-ready C2 and I do not recommend using it in any real environments. 

There are plenty of IOCs that are intrinsic to the methods applied (if you know them, you can change it) and network communication is completely naked at the moment (no options or transforms for headers).

## TODO:
### Priorities:
(implant)
- testing implant P2P communication/ fixing protocol
- testing COFF loader
- re-implement generic thread stack spoofing/ sleepobf
- redirector rotation (maybe)
- client request header configuration and metadata (definitely)
- implement COFF data cache (needs tested)
- write documentation

### C2 infrastructure:
- re-implement http listener
- automation of infraC2 (maybe)
- access control/ filtering (not sure yet)
- forwarding through reverse proxy (maybe)
- user database (definitely)

### Wish-List:
- hot-swap configs (sleep/redirectors)
- server response header configuration
- forking non-C2 traffic to webpage (filtering)
- implement indirect syscalls/proxying through kernbase/kern32
- operator logging
