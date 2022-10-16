@ECHO OFF
SET FILENAME=EamService.cs
SET NAMESPACE=EamService
SET OUTPUTDIR=%~dp0..\EamStubSlim

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\*.wsdl %~dp0wsdl\*.xsd
