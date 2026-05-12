# Codex Instructions

## AI Development Pipeline

Use the most capable AI model as the main orchestrator for non-trivial work.
It should first analyze the user's prompt, identify the real goal, split the work into
small independent tasks, and assign those tasks to simpler subagents when parallel
execution can reduce context usage, token usage, or turnaround time.

The orchestrator remains responsible for the final result: it should integrate the
subagents' findings or changes, resolve conflicts, verify the outcome, and keep edits
scoped to the requested work.

## Verification Pipeline

Do not start long-running application processes unless the user explicitly asks for it.
Avoid `dotnet run`, `Start-Process dotnet`, Blazor dev server launches, browser-driven checks,
or local backend/frontend hosting as default verification steps.

For backend, frontend, and shared library changes, use build/test commands only:

```powershell
dotnet restore .\Certification.Backend\Certification.Backend.csproj
dotnet restore .\Certification.Frontend\Certification.Frontend.csproj
dotnet restore .\UT\UT.csproj

dotnet build .\Certification.Backend\Certification.Backend.csproj --configuration Release --no-restore
dotnet build .\Certification.Frontend\Certification.Frontend.csproj --configuration Release --no-restore
dotnet test .\UT\UT.csproj --configuration Release --no-restore
```

For changes that affect the legacy client, also run:

```powershell
dotnet build .\CertificateManager.Client\CertificateManager.Client.csproj --configuration Release
```

If a change needs runtime/browser verification, state that it requires an explicit local run
and wait for the user's permission instead of starting processes automatically.

## Project Notes

- `Certification.Backend` is the current backend project.
- `Certification.Frontend` is the current Blazor WebAssembly frontend project.
- `CertificateManager.Client` is the legacy/client-side project and may still contain mirrored pages.
- Keep edits scoped and do not revert unrelated local changes.
