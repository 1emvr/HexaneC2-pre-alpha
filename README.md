# HexaneC2
### Overview:
This framework is a compilation of every publicly available resource I could think of with some very minimal UI/UX features. A good portion of the code is derived from https://github.com/HavocFramework/Havoc.

The implant is not 100% undetectable. There are plenty of IOCs that are intrinsic to the methods applied and network communication are completely naked.

This is meant to be a platform for me to expand with custom implementations and experimenting with new features later on.

### Todo:
- testing P2P communication
- testing COFF loading features
- implement coff data cache
- implement dll manual mapping: https://github.com/bats3c/DarkLoadLibrary
- implement indirect syscalls/proxying through kernelbase/kern32
- re-implement thread stack spoofing/ sleep obfuscation
- implement external listeners/redirectors
- write documentation/installation steps