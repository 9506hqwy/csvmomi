@ECHO OFF
SET FILENAME=PbmService.cs
SET NAMESPACE=PbmService
SET OUTPUTDIR=%~dp0..\PbmStubSlim

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\*.wsdl %~dp0wsdl\*.xsd
