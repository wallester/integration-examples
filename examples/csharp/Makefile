
default: 
	@msbuild App.sln /t:Build /p:Configuration=Release

deps:
	@nuget restore

run:
	@dotnet App/bin/Release/netcoreapp2.0/App.dll

