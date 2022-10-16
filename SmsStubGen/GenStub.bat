@ECHO OFF
SET FILENAME=SmsService.cs
SET NAMESPACE=SmsService
SET OUTPUTDIR=%~dp0..\SmsStubSlim

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\*.wsdl %~dp0wsdl\*.xsd
