@ECHO OFF
PUSHD %~dp0

SET STUB_FILENAME=VimService.cs
SET SRC_STUB_PATH=%~dp0%STUB_FILENAME%
SET DEST_STUB_PATH=%~dp0..\VimService\%STUB_FILENAME%

SET SERDE_FILENAME=VimService.XmlSerializers.cs
SET SRC_SERDE_PATH=%~dp0obj\Release\netcoreapp2.1\%SERDE_FILENAME%
SET DEST_SERDE_PATH=%~dp0..\VimService\%SERDE_FILENAME%

DEL "%DEST_SERDE_PATH%"
dotnet build -c Release
COPY "%SRC_SERDE_PATH%" "%DEST_SERDE_PATH%"
COPY "HttpNfcLeaseInfo.cs" "%~dp0..\VimService\HttpNfcLeaseInfo.cs"
COPY "HttpNfcLeaseState.cs" "%~dp0..\VimService\HttpNfcLeaseState.cs"

deno.exe run --allow-read --allow-write ..\Tools\SlimVimService.ts "%SRC_STUB_PATH%" "%DEST_STUB_PATH%"

POPD
