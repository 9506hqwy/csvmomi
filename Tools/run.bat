@ECHO OFF

SET TOOL=%~dp0
SET SRC=%TOOL%..\CsVmomi\

if "%EAM_REF_GUIDE%" == "" (
    ECHO error EAM_REF_GUIDE
    EXIT /B 1
)

if "%PBM_REF_GUIDE%" == "" (
    ECHO error PBM_REF_GUIDE
    EXIT /B 1
)

if "%SMS_REF_GUIDE%" == "" (
    ECHO error SMS_REF_GUIDE
    EXIT /B 1
)

if "%VIM_REF_GUIDE%" == "" (
    ECHO error VIM_REF_GUIDE
    EXIT /B 1
)

if "%VSLM_REF_GUIDE%" == "" (
    ECHO error VSLM_REF_GUIDE
    EXIT /B 1
)

deno run --allow-read "%TOOL%GenEamImplementation.ts" "%EAM_REF_GUIDE%" > "%SRC%EamClient.cs"
deno run --allow-read "%TOOL%GenEamInterface.ts" "%EAM_REF_GUIDE%" > "%SRC%IEamClient.cs"
deno run --allow-read "%TOOL%GenEamManagedObject.ts" "%EAM_REF_GUIDE%" > "%SRC%ManagedObject\GeneratedEam.cs"

deno run --allow-read "%TOOL%GenPbmImplementation.ts" "%PBM_REF_GUIDE%" > "%SRC%PbmClient.cs"
deno run --allow-read "%TOOL%GenPbmInterface.ts" "%PBM_REF_GUIDE%" > "%SRC%IPbmClient.cs"
deno run --allow-read "%TOOL%GenPbmManagedObject.ts" "%PBM_REF_GUIDE%" > "%SRC%ManagedObject\GeneratedPbm.cs"

deno run --allow-read "%TOOL%GenSmsImplementation.ts" "%SMS_REF_GUIDE%" > "%SRC%SmsClient.cs"
deno run --allow-read "%TOOL%GenSmsInterface.ts" "%SMS_REF_GUIDE%" > "%SRC%ISmsClient.cs"
deno run --allow-read "%TOOL%GenSmsManagedObject.ts" "%SMS_REF_GUIDE%" > "%SRC%ManagedObject\GeneratedSms.cs"

deno run --allow-read "%TOOL%GenVimImplementation.ts" "%VIM_REF_GUIDE%" > "%SRC%VimClient.cs"
deno run --allow-read "%TOOL%GenVimInterface.ts" "%VIM_REF_GUIDE%" > "%SRC%IVimClient.cs"
deno run --allow-read "%TOOL%GenVimManagedObject.ts" "%VIM_REF_GUIDE%" > "%SRC%ManagedObject\GeneratedVim.cs"

deno run --allow-read "%TOOL%GenVslmImplementation.ts" "%VSLM_REF_GUIDE%" > "%SRC%VslmClient.cs"
deno run --allow-read "%TOOL%GenVslmInterface.ts" "%VSLM_REF_GUIDE%" > "%SRC%IVslmClient.cs"
deno run --allow-read "%TOOL%GenVslmManagedObject.ts" "%VSLM_REF_GUIDE%" > "%SRC%ManagedObject\GeneratedVslm.cs"
