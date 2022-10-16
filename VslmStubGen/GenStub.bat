@ECHO OFF
SET FILENAME=VslmService.cs
SET NAMESPACE=VslmService
SET OUTPUTDIR=%~dp0..\VslmStubSlim

DEL "%OUTPUTDIR%\%FILENAME%"
dotnet-svcutil --outputDir "%OUTPUTDIR%" --noLogo --verbosity Debug --outputFile %FILENAME% --namespace *,%NAMESPACE% --serializer XmlSerializer --wrapped --targetFramework netstandard2.0 %~dp0wsdl\*.wsdl %~dp0wsdl\*.xsd
