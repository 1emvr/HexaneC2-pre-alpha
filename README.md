# HexaneC2
### Overview:
This framework is a compilation of every publicly available resource I could think of with some very minimal UI/UX features. A good portion of the code is derived from https://github.com/HavocFramework/Havoc.

The idea is to lay the groundwork for custom implementations and experiment with new features later on. This is not a production-ready C2 and I do not recommend using it in any real environments. 

The implant is not 100% undetectable. There are plenty of IOCs that are intrinsic to the methods applied (if you know them, you can change it) and network communication is completely naked at the moment.

### Priorities:
- testing P2P communication
- testing COFF loader
- re-implement thread stack spoofing/ sleepobf
- implement http listener
- automation of infraC2
- write documentation

### Wish-List:
- implement dll manual mapping: https://github.com/bats3c/DarkLoadLibrary
- implement indirect syscalls/proxying through kernelbase/kern32
- hashing process strings
- implement coff data cache
