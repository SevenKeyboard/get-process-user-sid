#Requires AutoHotkey v2.0.0+
;==============================================================
; getProcessUserSid — Returns the current process user SID as a string via access token (OpenProcessToken/GetTokenInformation)
;
; GitHub: https://github.com/SevenKeyboard/get-process-user-sid
; Author: SevenKeyboard Ltd. (2026)
; License: MIT License
;==============================================================

/*
Example Usage:
    msgbox(getProcessUserSid()) ;  "S-1-5-21-12345678-12345678-12345678-1000"
*/

class VersionManager_getProcessUserSid
{
    static _ := this._init()
    static _init()    {
        global
        GETPROCESSUSERSID_VERSION := "1.0.0"
    }
}
getProcessUserSid()    {
    static TOKEN_QUERY  := 0x0008
        ,TokenUser      := 1
    if (!dllCall("Advapi32.dll\OpenProcessToken"
            ,"Ptr",dllCall("Kernel32.dll\GetCurrentProcess", "Ptr") ;  -1
            ,"UInt",TOKEN_QUERY
            ,"Ptr*",&tokenHandle := 0
            ,"Int"))    {
        return ""
    }
    dllCall("Advapi32.dll\GetTokenInformation"
        ,"Ptr",tokenHandle
        ,"Int",TokenUser
        ,"Ptr",0
        ,"UInt",0
        ,"UInt*",&tokenInformationLength := 0
        ,"Int")
    if (tokenInformationLength == 0)    {
        if (tokenHandle)
            dllCall("Kernel32.dll\CloseHandle", "Ptr",tokenHandle, "Int"), tokenHandle := 0
        return ""
    }
    tokenInformation := buffer(tokenInformationLength, 0)
    bResult := dllCall("Advapi32.dll\GetTokenInformation"
        ,"Ptr",tokenHandle
        ,"Int",TokenUser
        ,"Ptr",tokenInformation.Ptr
        ,"UInt",tokenInformationLength
        ,"UInt*",&_ := 0
        ,"Int")
    if (tokenHandle)
        dllCall("Kernel32.dll\CloseHandle", "Ptr",tokenHandle, "Int"), tokenHandle := 0
    if (!bResult)
        return ""
    /*
    typedef struct _TOKEN_USER {
      SID_AND_ATTRIBUTES User;
    } TOKEN_USER, *PTOKEN_USER;
    */
    /*
    typedef struct _SID_AND_ATTRIBUTES {
    #if ...
      PISID Sid;
    #else
      PSID  Sid;
    #endif
      DWORD Attributes;
    } SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;
    */
    if (!pSid := numGet(tokenInformation, 0, "Ptr"))
        return ""
    if (!dllCall("Advapi32.dll\ConvertSidToStringSidW", "Ptr",pSid, "Ptr*",&pStringSid := 0, "Int"))
        return ""
    stringSid := strGet(pStringSid, "UTF-16")
    dllCall("Kernel32.dll\LocalFree", "Ptr",pStringSid, "Ptr")
    return stringSid
}