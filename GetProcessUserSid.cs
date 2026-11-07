//==============================================================
// getProcessUserSid - Returns the current process user SID via its access token.
// C# port of main-ahkv1.1/getProcessUserSid.ahk.
//
// GitHub: https://github.com/SevenKeyboard/get-process-user-sid
// Author: SevenKeyboard Ltd. (2026)
// License: MIT License
//==============================================================

using System.Runtime.InteropServices;

namespace SevenKeyboard;

/// <summary>Reads the user SID from the current process's primary token.</summary>
public static partial class GetProcessUserSid
{
    /// <summary>
    /// Returns the current process user SID, or an empty string on native failure.
    /// Always queries the process token, even when the calling thread impersonates a user.
    /// </summary>
    public static string Get() => GetForProcess(GetCurrentProcess());

    // Kept internal so the smoke test can exercise a real invalid-process failure.
    internal static unsafe string GetForProcess(nint process)
    {
        const uint TokenQuery = 0x0008;
        const int TokenUser = 1;

        if (OpenProcessToken(process, TokenQuery, out nint token) == 0)
            return string.Empty;

        void* information = null;
        nint stringSid = 0;
        try
        {
            // Like AHK, use the required size from the initial sizing call.
            GetTokenInformation(token, TokenUser, null, 0, out uint length);
            if (length < (uint)sizeof(nint))
                return string.Empty;

            information = NativeMemory.AllocZeroed(length);
            if (GetTokenInformation(token, TokenUser, information, length, out _) == 0)
                return string.Empty;

            // TOKEN_USER begins with SID_AND_ATTRIBUTES.Sid on both x86 and x64.
            nint sid = *(nint*)information;
            if (sid == 0 || ConvertSidToStringSidW(sid, out stringSid) == 0)
                return string.Empty;

            return Marshal.PtrToStringUni(stringSid) ?? string.Empty;
        }
        finally
        {
            if (stringSid != 0)
                LocalFree(stringSid);
            NativeMemory.Free(information);
            CloseHandle(token);
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("advapi32.dll")]
    private static partial int OpenProcessToken(nint process, uint desiredAccess, out nint token);

    [LibraryImport("advapi32.dll")]
    private static unsafe partial int GetTokenInformation(
        nint token, int informationClass, void* information, uint length, out uint returnLength);

    [LibraryImport("advapi32.dll")]
    private static partial int ConvertSidToStringSidW(nint sid, out nint stringSid);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);

    [LibraryImport("kernel32.dll")]
    private static partial int CloseHandle(nint handle);
}
