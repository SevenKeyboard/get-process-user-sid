# GetProcessUserSid

C# port of [getProcessUserSid.ahk](https://github.com/SevenKeyboard/get-process-user-sid/blob/main-ahkv1.1/getProcessUserSid.ahk).
Returns the current Windows process user's SID as a string.

Targets .NET 10 on Windows, x64 and x86; trimming and NativeAOT compatible.

```csharp
string sid = SevenKeyboard.GetProcessUserSid.Get();
Console.WriteLine(sid); // S-1-5-21-...-1000
```

Always queries the **process token**, including during thread impersonation,
requesting only `TOKEN_QUERY`. Native failure returns `string.Empty`, matching
AHK. Token handles and native buffers are released deterministically.

Run the smoke checks (use `win-x86` and `.artifacts/x86` for x86):

```powershell
dotnet run --project smoke -c Release -r win-x64 --artifacts-path .artifacts/x64
```

MIT License. Copyright (c) 2026 SevenKeyboard Ltd. See [LICENSE](LICENSE).
