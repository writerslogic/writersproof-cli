# C# / XAML Style Guide

Project-specific conventions for the CPoE Windows desktop application (`apps/cpoe_windows/`), built with WinUI 3 and .NET 8.

## 1. Project Configuration

- **Target:** `net8.0-windows10.0.19041.0` (Windows 10 Build 19041+)
- **Platforms:** x86, x64, ARM64
- **Nullable Reference Types:** Enabled globally (`<Nullable>enable</Nullable>`)
- **Implicit Usings:** Enabled (`<ImplicitUsings>enable</ImplicitUsings>`)
- **Language Version:** C# 11+
- **Unsafe blocks:** Enabled only in main project, scoped to P/Invoke files (`TpmInterop.cs`, `IpcNamedPipe.cs`)

## 2. File Structure

- **File-scoped namespaces** (no braces):

```csharp
namespace WritersLogic.Services;
```

- **Namespace hierarchy:**
  - `WritersLogic` -- root
  - `WritersLogic.Services` -- services (AppLogger, SecurityService, etc.)
  - `WritersLogic.Controls` -- custom XAML controls
  - `WritersLogic.Pages` -- page views
  - `WritersLogic.Models` -- data models
  - `WritersLogic.Dialogs` -- dialog windows
  - `WritersLogic.Tests` -- unit tests

## 3. Import Ordering

Group `using` statements logically, alphabetical within groups:

```csharp
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppLifecycle;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.ApplicationModel.Activation;
using Windows.Storage;
using WritersLogic.Services;
```

## 4. Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Classes, structs, enums | PascalCase | `AppLogger`, `SecurityService` |
| Interfaces | I-prefix + PascalCase | `IWLDBridge` |
| Public properties | PascalCase | `DataPoints`, `StrokeColor` |
| Private fields | `_camelCase` (leading underscore) | `_mainWindow`, `_pollingCts` |
| Static readonly | PascalCase or `_camelCase` | `LogLock`, `_fileLock` |
| Public methods | PascalCase | `Initialize`, `VerifyAuthenticodeSignature` |
| Private methods | PascalCase | `PerformSecurityChecks` |
| Async methods | PascalCase + `Async` suffix | `InitializeStoreAsync`, `ShowLockScreenAsync` |
| Event handlers | `On` prefix | `OnFileChangeDetected`, `OnShowWindowRequested` |
| Constants (P/Invoke) | UPPER_SNAKE_CASE | `WTD_UI_NONE`, `WTD_REVOKE_NONE` |
| Enum values | PascalCase | `BadgeStatus.Pending` |
| XAML resource keys | PascalCase | `WLDAccentColor`, `CardPadding` |

## 5. Nullable Reference Types

Nullable is enabled globally. Follow these patterns:

```csharp
// Explicit nullability
private MainWindow? _mainWindow;

// Null-coalescing
label ?? defaultLabel

// Guard clauses (return early)
if (_mainWindow?.Content.XamlRoot == null) return;
if (string.IsNullOrEmpty(hash)) return;

// Null-forgiving (sparingly, only when provably non-null)
result!.Version

// Optional in records
ValidationResult(bool IsValid, string? ErrorMessage = null)
```

## 6. Async / Await

- `async void` only for event handlers (`OnLaunched`, UI callbacks).
- All other async methods return `Task` or `Task<T>` with `Async` suffix.
- Use `CancellationToken` parameters explicitly:

```csharp
private async Task StartStatusPollingAsync(CancellationToken cancellationToken)
{
    while (!cancellationToken.IsCancellationRequested)
    {
        await Task.Delay(1000, cancellationToken);
    }
}
```

- Fire-and-forget pattern always includes try-catch:

```csharp
_ = Task.Run(async () =>
{
    try { await InitializeStoreAsync(); }
    catch (Exception ex) { AppLogger.Error($"Store init failed: {ex.Message}"); }
});
```

## 7. Error Handling

- Centralized `AppLogger` static class with caller info attributes.
- Log levels: Trace, Debug, Info, Warn, Error.
- Always log with context:

```csharp
AppLogger.Error($"Store initialization failed: {ex.Message}");
SecurityService.LogEvent(SecurityService.SecurityEventType.AppExited,
    $"Unhandled exception: {e.Exception?.GetType().Name}: {e.Exception?.Message}");
```

- Wrap critical operations in try-catch with meaningful messages.
- P/Invoke calls always wrapped with error handling.

## 8. Documentation

XML doc comments (`///`) on all public types and methods:

```csharp
/// <summary>
/// Structured application logger. Debug build: all levels to Debug.WriteLine.
/// Release build: Warning+ to rotating file (%LOCALAPPDATA%\WritersLogic\app.log, 5MB rotate).
/// </summary>
public static class AppLogger

/// <summary>
/// Performs runtime security checks including debugger detection and assembly integrity.
/// </summary>
private bool PerformSecurityChecks()
```

TODO comments reference issue numbers: `// TODO(M-085): description...`

## 9. XAML Conventions

### Bindings

Use **x:Bind** (compiled binding), not `{Binding}`:

```xaml
Text="{x:Bind Value, Mode=OneWay}"
AutomationProperties.Name="{x:Bind Label, Mode=OneWay}"
```

### Control Naming

Semantic names with `x:Name`: `StatusDot`, `StatusLabel`, `ValueText`.

### Resource Tokens

Centralized in `Themes/DesignTokens.xaml` and `App.xaml`:

- Colors: `WLDAccentColor`, `WLDSuccessColor`, `WLDWarningColor`, `WLDErrorColor`
- Brushes: `WLDAccentBrush`, `WLDSuccessBrush`, `WLDErrorBrush`
- Spacing: `PagePadding`, `CardPadding`, `SmallSpacing`, `MediumSpacing`, `LargeSpacing`
- Heatmap: `HeatmapLevel0Brush` through `HeatmapLevel4Brush`

### Theme Support

Support Light, Dark, and High Contrast themes via `ResourceDictionary.ThemeDictionaries`.

### Accessibility

- `AutomationProperties.Name` on all interactive controls.
- `AutomationProperties.LiveSetting="Polite"` on status indicators.

### Custom Controls

```csharp
public static readonly DependencyProperty ValueProperty =
    DependencyProperty.Register(nameof(Value), typeof(string), typeof(StatCard),
        new PropertyMetadata("0"));

public string Value
{
    get => (string)GetValue(ValueProperty);
    set => SetValue(ValueProperty, value);
}
```

## 10. Dependency Properties

Use change handlers for reactive updates:

```csharp
public static readonly DependencyProperty StatusProperty =
    DependencyProperty.Register(nameof(Status), typeof(BadgeStatus), typeof(StatusBadge),
        new PropertyMetadata(BadgeStatus.Pending, OnStatusChanged));

private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
{
    if (d is StatusBadge badge)
        badge.UpdateVisual();
}
```

## 11. Static Service Pattern

Static service classes for cross-cutting concerns:

```csharp
public static class AppLogger
{
    private static readonly object _fileLock = new();
    private static LogLevel _minLevel = LogLevel.Info;

    private static void WriteToFile(string line)
    {
        lock (_fileLock) { /* write operation */ }
    }
}
```

- Thread safety via `lock` objects and `Interlocked` operations.
- `ServiceLocator` for singleton instances (e.g., `EntitlementManager`).

## 12. Conditional Compilation

```csharp
#if !DEBUG
    // Release-only: security checks, file logging
#endif

#if DEBUG
    System.Diagnostics.Debug.WriteLine(formatted);
#else
    if (level <= LogLevel.Warn) { WriteToFile(formatted); }
#endif
```

## 13. JSON Serialization (Rust Interop)

Use `System.Text.Json` with snake_case naming for IPC compatibility with the Rust engine:

```csharp
[JsonPropertyName("file_path")]
public string FilePath { get; set; }

[JsonPropertyName("tracked_files")]
public List<TrackedFile> TrackedFiles { get; set; }
```

Externally-tagged enums match Rust serde format via custom `JsonConverter`.

## 14. Testing

- **Framework:** xUnit + FluentAssertions + Moq
- Test project: `net8.0` (no WinUI dependency)
- `[Fact]` for unit tests, `[Theory]` with `[InlineData]` for parameterized tests.

```csharp
[Fact]
public void Deserialize_GetStatus_Response()
{
    var result = JsonSerializer.Deserialize<IpcMessage>(json, options);
    result.Should().NotBeNull();
    result.Should().BeOfType<IpcMessage.GetStatus>();
    result.TrackedFiles.Should().HaveCount(2);
}
```

## 15. Security

- Authenticode signature verification via P/Invoke (`WinVerifyTrust`).
- DPAPI for sensitive data protection.
- `StructLayout` marshaling with explicit field ordering for P/Invoke.
- Debugger detection and assembly integrity checks in release builds.
- Input validation via `ValidationService` with regex patterns and `ValidationResult` records.
