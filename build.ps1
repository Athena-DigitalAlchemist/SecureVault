# Build configuration
$configuration = "Release"
$runtime = "win-x64"
$framework = "net8.0-windows"
$outputPath = "./publish"
$dotnetPath = "C:\Program Files\dotnet\dotnet.exe"

Write-Host " Building SecureVault..." -ForegroundColor Cyan

# Restore dependencies
Write-Host " Restoring packages..." -ForegroundColor Yellow
& $dotnetPath restore
if ($LASTEXITCODE -ne 0) {
    Write-Host " Package restore failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Build solution
Write-Host " Building solution..." -ForegroundColor Yellow
& $dotnetPath build --configuration $configuration
if ($LASTEXITCODE -ne 0) {
    Write-Host " Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Run tests
Write-Host " Running tests..." -ForegroundColor Yellow
& $dotnetPath test --configuration $configuration --no-build
if ($LASTEXITCODE -ne 0) {
    Write-Host " Tests failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Publish application
Write-Host " Publishing application..." -ForegroundColor Yellow
& $dotnetPath publish src/SecureVault.UI/SecureVault.UI.csproj `
    --configuration $configuration `
    --runtime $runtime `
    --framework $framework `
    --self-contained true `
    --output $outputPath `
    -p:PublishSingleFile=true `
    -p:PublishTrimmed=true `
    -p:IncludeNativeLibrariesForSelfExtract=true

if ($LASTEXITCODE -ne 0) {
    Write-Host " Publish failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Copy additional files
Write-Host " Copying additional files..." -ForegroundColor Yellow
Copy-Item "README.md" -Destination "$outputPath/README.md" -Force
Copy-Item "docs/*" -Destination "$outputPath/docs/" -Force -Recurse

Write-Host " Build completed successfully!" -ForegroundColor Green
Write-Host " Output location: $((Get-Item $outputPath).FullName)" -ForegroundColor Cyan
