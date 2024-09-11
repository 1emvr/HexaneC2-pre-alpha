# HexaneC2
### Overview:
This framework is a compilation of every publicly available resource I could think of with some very minimal UI/UX features. A good portion of the code is derived from https://github.com/HavocFramework/Havoc.

The idea is to lay the groundwork for custom implementations and experiment with new features later on. This is not a production-ready C2 and I do not recommend using it in any real engagements. 

The implant is not 100% undetectable. There are plenty of IOCs that are intrinsic to the methods applied (if you know them, you can change it) and network communication is completely naked at the moment.

### Todo:
- testing P2P communication
- testing coff loading features
- implement coff data cache
- implement dll manual mapping: https://github.com/bats3c/DarkLoadLibrary
- implement indirect syscalls/proxying through kernelbase/kern32
- re-implement thread stack spoofing/ sleep obfuscation
- implement external listeners/redirectors
- porting entire server/listener to Rust for stability
- write documentation
