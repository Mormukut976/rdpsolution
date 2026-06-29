using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("OpenRemote Agent currently supports Windows hosts only.");
    return 2;
}

var settings = AgentSettings.Load(args);
if (settings is null)
{
    Console.Error.WriteLine(
        "Configure ServerUrl and AgentToken in agentsettings.json, " +
        "or set OPENREMOTE_SERVER and OPENREMOTE_AGENT_TOKEN.");
    return 2;
}

using var http = new HttpClient
{
    BaseAddress = new Uri(settings.ServerUrl.TrimEnd('/') + "/"),
    Timeout = TimeSpan.FromSeconds(20),
};
http.DefaultRequestHeaders.Authorization =
    new AuthenticationHeaderValue("Bearer", settings.AgentToken);
http.DefaultRequestHeaders.UserAgent.ParseAdd("OpenRemote-Agent/0.1.0");

Console.WriteLine($"OpenRemote Agent started on {Environment.MachineName}");
Console.WriteLine($"Control plane: {http.BaseAddress}");

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

var monitor = new WindowsMonitor();
var heartbeatCount = 0;

while (!shutdown.IsCancellationRequested)
{
    try
    {
        var metrics = monitor.Read();
        var heartbeat = new AgentHeartbeat(
            $"{Environment.OSVersion} ({RuntimeInformation.OSArchitecture})",
            metrics.CpuPercent,
            metrics.MemoryPercent,
            new Dictionary<string, object?>
            {
                ["machineName"] = Environment.MachineName,
                ["framework"] = RuntimeInformation.FrameworkDescription,
                ["processorCount"] = Environment.ProcessorCount,
                ["agentVersion"] = "0.1.0",
            }
        );
        using var response = await http.PostAsJsonAsync(
            "api/agent/heartbeat",
            heartbeat,
            shutdown.Token
        );
        response.EnsureSuccessStatusCode();

        heartbeatCount++;
        if (heartbeatCount == 1 || heartbeatCount % 10 == 0)
        {
            var configuration = await http.GetFromJsonAsync<AgentConfiguration>(
                "api/agent/config",
                shutdown.Token
            );
            Console.WriteLine(
                $"[{DateTimeOffset.Now:u}] Online · " +
                $"{configuration?.Applications.Count ?? 0} published applications"
            );
        }
    }
    catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
    {
        break;
    }
    catch (Exception error)
    {
        Console.Error.WriteLine($"[{DateTimeOffset.Now:u}] Heartbeat failed: {error.Message}");
    }

    try
    {
        await Task.Delay(TimeSpan.FromSeconds(settings.HeartbeatSeconds), shutdown.Token);
    }
    catch (OperationCanceledException)
    {
        break;
    }
}

Console.WriteLine("OpenRemote Agent stopped.");
return 0;

sealed record AgentHeartbeat(
    string OsInfo,
    double CpuPercent,
    double MemoryPercent,
    Dictionary<string, object?> Metadata
);

sealed record PublishedApplication(
    string Id,
    string Name,
    string Mode,
    string RemoteApp,
    string WorkingDirectory,
    string Arguments
);

sealed record AgentConfiguration(string HostId, List<PublishedApplication> Applications);

sealed record AgentSettings(string ServerUrl, string AgentToken, int HeartbeatSeconds)
{
    public static AgentSettings? Load(string[] args)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "agentsettings.json");
        string? serverUrl = Environment.GetEnvironmentVariable("OPENREMOTE_SERVER");
        string? token = Environment.GetEnvironmentVariable("OPENREMOTE_AGENT_TOKEN");
        var interval = 30;

        if (File.Exists(path))
        {
            try
            {
                var fileSettings = JsonSerializer.Deserialize<AgentSettings>(
                    File.ReadAllText(path),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );
                serverUrl ??= fileSettings?.ServerUrl;
                token ??= fileSettings?.AgentToken;
                interval = fileSettings?.HeartbeatSeconds ?? interval;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"Could not read {path}: {error.Message}");
            }
        }

        for (var index = 0; index < args.Length - 1; index++)
        {
            if (args[index] == "--server") serverUrl = args[++index];
            else if (args[index] == "--token") token = args[++index];
            else if (args[index] == "--interval" && int.TryParse(args[++index], out var parsed))
                interval = parsed;
        }

        if (
            string.IsNullOrWhiteSpace(serverUrl)
            || !Uri.TryCreate(serverUrl, UriKind.Absolute, out _)
            || string.IsNullOrWhiteSpace(token)
        )
        {
            return null;
        }

        return new AgentSettings(serverUrl, token, Math.Clamp(interval, 10, 300));
    }
}

sealed class WindowsMonitor
{
    private ulong _previousIdle;
    private ulong _previousKernel;
    private ulong _previousUser;

    public (double CpuPercent, double MemoryPercent) Read()
    {
        var cpu = ReadCpu();
        var memory = ReadMemory();
        return (Math.Round(cpu, 1), Math.Round(memory, 1));
    }

    private double ReadCpu()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user)) return 0;
        var idleValue = ToUInt64(idle);
        var kernelValue = ToUInt64(kernel);
        var userValue = ToUInt64(user);

        if (_previousKernel == 0)
        {
            _previousIdle = idleValue;
            _previousKernel = kernelValue;
            _previousUser = userValue;
            return 0;
        }

        var idleDelta = idleValue - _previousIdle;
        var kernelDelta = kernelValue - _previousKernel;
        var userDelta = userValue - _previousUser;
        var total = kernelDelta + userDelta;

        _previousIdle = idleValue;
        _previousKernel = kernelValue;
        _previousUser = userValue;
        return total == 0 ? 0 : Math.Clamp((1d - (double)idleDelta / total) * 100d, 0d, 100d);
    }

    private static double ReadMemory()
    {
        var status = new MemoryStatusEx();
        return GlobalMemoryStatusEx(status) ? status.MemoryLoad : 0;
    }

    private static ulong ToUInt64(FileTime value) =>
        ((ulong)value.HighDateTime << 32) | value.LowDateTime;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(
        out FileTime idleTime,
        out FileTime kernelTime,
        out FileTime userTime
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatusEx buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private sealed class MemoryStatusEx
    {
        public uint Length = (uint)Marshal.SizeOf<MemoryStatusEx>();
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }
}
