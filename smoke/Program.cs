//==============================================================
// getProcessUserSid - Native behavior and resource smoke checks.
//
// GitHub: https://github.com/SevenKeyboard/get-process-user-sid
// Author: SevenKeyboard Ltd. (2026)
// License: MIT License
//==============================================================

using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using SevenKeyboard;

internal static unsafe partial class Program
{
    private const uint TokenQuery = 0x0008;
    private static readonly nint Process = new(-1);
    private static readonly nint Thread = new(-2);

    private static int Main()
    {
        try
        {
            // Independently decode the native SID bytes, without ConvertSidToStringSid.
            string expected = ReadProcessSid(out int error);
            Check(error == 0 && expected.Length != 0, $"Native oracle failed: {error}");
            Check(GetProcessUserSid.Get() == expected, "Native process SID mismatch");
            Console.WriteLine($"PASS native SID ({RuntimeInformation.ProcessArchitecture}): {expected}");

            Check(OpenProcessToken(0, TokenQuery, out _) == 0, "Invalid handle unexpectedly succeeded");
            Check(Marshal.GetLastPInvokeError() == 6, "Expected ERROR_INVALID_HANDLE");
            Check(GetProcessUserSid.GetForProcess(0) == string.Empty, "Native failure must return empty");
            Console.WriteLine("PASS native invalid-process failure returns empty");

            TestImpersonation(expected);
            TestResourceCycles(expected);
            Console.WriteLine("PASS all smoke checks");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"FAIL {exception}");
            return 1;
        }
    }

    private static void TestImpersonation(string expected)
    {
        // A fresh smoke process must not disturb a pre-existing thread identity.
        int opened = OpenThreadToken(Thread, TokenQuery, 1, out nint existing);
        if (opened != 0)
        {
            CloseHandle(existing);
            throw new InvalidOperationException("Run the smoke in a fresh, non-impersonating process.");
        }
        Check(Marshal.GetLastPInvokeError() == 1008, "Expected ERROR_NO_TOKEN");

        NativeCheck(ImpersonateSelf(2), "ImpersonateSelf");
        try
        {
            NativeCheck(OpenThreadToken(Thread, TokenQuery, 1, out nint threadToken), "OpenThreadToken");
            try
            {
                Check(ReadTokenSid(threadToken) == expected, "Unexpected self impersonation SID");
                Check(GetProcessUserSid.Get() == expected, "Process SID during self impersonation");
            }
            finally
            {
                CloseHandle(threadToken);
            }
        }
        finally
        {
            Revert();
        }
        Console.WriteLine("PASS process SID with an active self-impersonation token");

        // No credentials or account changes: exercise a distinct anonymous thread identity.
        // Windows can deny opening the process token in this context; AHK then returns "".
        if (ImpersonateAnonymousToken(Thread) == 0)
        {
            Console.WriteLine($"SKIP anonymous impersonation: Win32 {Marshal.GetLastPInvokeError()}");
            return;
        }

        string nativeResult;
        string actual;
        int nativeError;
        try
        {
            nativeResult = ReadProcessSid(out nativeError);
            actual = GetProcessUserSid.Get();
        }
        finally
        {
            Revert();
        }
        Check(nativeError == 0 ? nativeResult == expected : nativeResult == string.Empty,
            "Anonymous native oracle returned the thread SID");
        Check(actual == nativeResult, "Anonymous impersonation must match process-token behavior");
        Check(GetProcessUserSid.Get() == expected, "Process SID after reverting impersonation");
        Console.WriteLine(nativeError == 0
            ? "PASS process SID under distinct anonymous impersonation"
            : $"PASS anonymous impersonation: native failure {nativeError} maps to empty");
    }

    private static void TestResourceCycles(string expected)
    {
        // Warm the same allocation volume before measuring retained native resources.
        for (int i = 0; i < 100_000; i++)
        {
            Check(GetProcessUserSid.Get() == expected, "Warm-up SID");
            Check(GetProcessUserSid.GetForProcess(0) == string.Empty, "Warm-up failure");
        }
        Collect();
        long bytesBefore = PrivateBytes();
        long managedBefore = GC.GetGCMemoryInfo().TotalCommittedBytes;
        uint handlesBefore = HandleCount();
        for (int i = 0; i < 100_000; i++)
        {
            Check(GetProcessUserSid.Get() == expected, "Repeated SID");
            Check(GetProcessUserSid.GetForProcess(0) == string.Empty, "Repeated native failure");
        }
        // Measure handles before GC so finalizers cannot hide deferred token cleanup.
        uint handlesAfter = HandleCount();
        Collect();
        long bytesAfter = PrivateBytes();
        // Exclude managed GC segment growth from this native-resource leak check.
        long managedGrowth = GC.GetGCMemoryInfo().TotalCommittedBytes - managedBefore;
        long growth = bytesAfter - bytesBefore - managedGrowth;
        Check(handlesAfter <= handlesBefore + 2, $"Handle growth: {handlesBefore} -> {handlesAfter}");
        Check(growth < 4 * 1024 * 1024, $"Private-byte growth: {growth}");
        Console.WriteLine($"PASS 100,000 success/failure cycles: handles {handlesBefore} -> {handlesAfter}, native private-byte delta {growth}");
    }

    private static string ReadProcessSid(out int error)
    {
        if (OpenProcessToken(Process, TokenQuery, out nint token) == 0)
        {
            error = Marshal.GetLastPInvokeError();
            return string.Empty;
        }
        try
        {
            error = 0;
            return ReadTokenSid(token);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string ReadTokenSid(nint token)
    {
        GetTokenInformation(token, 1, null, 0, out uint length);
        Check(length >= (uint)sizeof(nint), "Native TOKEN_USER length");
        byte* buffer = (byte*)NativeMemory.Alloc(length);
        try
        {
            NativeCheck(GetTokenInformation(token, 1, buffer, length, out _), "GetTokenInformation");
            byte* sid = *(byte**)buffer;
            Check(IsValidSid(sid) != 0, "Native SID validation");
            ulong authority = 0;
            for (int i = 2; i < 8; i++)
                authority = (authority << 8) | sid[i];
            var result = new StringBuilder();
            result.Append("S-").Append(sid[0].ToString(CultureInfo.InvariantCulture)).Append('-');
            // Authorities exceeding 32 bits use six-byte hexadecimal SID notation.
            result.Append(authority > uint.MaxValue
                ? "0x" + authority.ToString("x12", CultureInfo.InvariantCulture)
                : authority.ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < sid[1]; i++)
                result.Append('-').Append(((uint*)(sid + 8))[i].ToString(CultureInfo.InvariantCulture));
            return result.ToString();
        }
        finally
        {
            NativeMemory.Free(buffer);
        }
    }

    private static void Revert()
    {
        if (RevertToSelf() == 0)
            Environment.FailFast("Unable to revert test thread impersonation.");
    }

    private static uint HandleCount()
    {
        NativeCheck(GetProcessHandleCount(Process, out uint count), "GetProcessHandleCount");
        return count;
    }

    private static long PrivateBytes()
    {
        MemoryCounters counters = default;
        counters.Size = (uint)sizeof(MemoryCounters);
        NativeCheck(GetProcessMemoryInfo(Process, &counters, counters.Size), "GetProcessMemoryInfo");
        return (long)counters.PrivateUsage;
    }

    private static void Collect()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static void NativeCheck(int result, string operation)
    {
        if (result == 0)
            throw new Win32Exception(Marshal.GetLastPInvokeError(), operation);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryCounters
    {
        internal uint Size;
        internal uint PageFaultCount;
        internal nuint PeakWorkingSetSize;
        internal nuint WorkingSetSize;
        internal nuint QuotaPeakPagedPoolUsage;
        internal nuint QuotaPagedPoolUsage;
        internal nuint QuotaPeakNonPagedPoolUsage;
        internal nuint QuotaNonPagedPoolUsage;
        internal nuint PagefileUsage;
        internal nuint PeakPagefileUsage;
        internal nuint PrivateUsage;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int OpenProcessToken(nint process, uint access, out nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int OpenThreadToken(nint thread, uint access, int openAsSelf, out nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int GetTokenInformation(nint token, int informationClass, void* buffer,
        uint length, out uint requiredLength);

    [LibraryImport("advapi32.dll")]
    private static partial int IsValidSid(void* sid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int ImpersonateSelf(int level);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int ImpersonateAnonymousToken(nint thread);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int RevertToSelf();

    [LibraryImport("kernel32.dll")]
    private static partial int CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int GetProcessHandleCount(nint process, out uint count);

    [LibraryImport("psapi.dll", SetLastError = true)]
    private static partial int GetProcessMemoryInfo(nint process, MemoryCounters* counters, uint size);
}
