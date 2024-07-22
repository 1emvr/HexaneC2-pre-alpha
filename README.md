HexaneC2 BYOS (Bring your own Sleep/Spoofing)

- anything that uses ContextInit() must include start.asm + xxx.ld
- corelib does not need any context. It only references Ctx-> and the main module should be the one that provides it
- corelib would need to have it's definitions for TXT_SECTION(lib, x) specified separately between both translation units
