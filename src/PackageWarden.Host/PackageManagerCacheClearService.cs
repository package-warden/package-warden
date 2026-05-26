// Copyright 2026 Patrick T. Dwyer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Proxy.Gem;
using PackageWarden.Proxy.Golang;
using PackageWarden.Proxy.Npm;
using PackageWarden.Proxy.NuGet;
using PackageWarden.Proxy.PyPI;

namespace PackageWarden.Host;

public class PackageManagerCacheClearService : BackgroundService
{
    private readonly TimeSpan _interval;
    private readonly IOptions<NpmProxyOptions> _npm;
    private readonly IOptions<NuGetProxyOptions> _nuget;
    private readonly IOptions<PyPIProxyOptions> _pypi;
    private readonly IOptions<GemProxyOptions> _gem;
    private readonly IOptions<GolangProxyOptions> _golang;
    private readonly ILogger<PackageManagerCacheClearService> _logger;

    public PackageManagerCacheClearService(
        IOptions<PackageWardenOptions> opts,
        IOptions<NpmProxyOptions> npm,
        IOptions<NuGetProxyOptions> nuget,
        IOptions<PyPIProxyOptions> pypi,
        IOptions<GemProxyOptions> gem,
        IOptions<GolangProxyOptions> golang,
        ILogger<PackageManagerCacheClearService> logger)
    {
        _interval = TimeSpan.FromMinutes(opts.Value.PackageManagerCacheClear.IntervalMinutes);
        _npm = npm;
        _nuget = nuget;
        _pypi = pypi;
        _gem = gem;
        _golang = golang;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(_interval, stoppingToken);
            await ClearCachesAsync(stoppingToken);
        }
    }

    private async Task ClearCachesAsync(CancellationToken ct)
    {
        if (_npm.Value.Enabled)
            await RunCommandAsync("npm", "npm cache clean --force", ct);
        if (_nuget.Value.Enabled)
            await RunCommandAsync("nuget", "dotnet nuget locals all --clear", ct);
        if (_pypi.Value.Enabled)
            await RunCommandAsync("pypi", "pip cache purge", ct);
        if (_gem.Value.Enabled)
            await RunCommandAsync("gem", "gem cleanup", ct);
        if (_golang.Value.Enabled)
            await RunCommandAsync("golang", "go clean -modcache", ct);
    }

    private async Task RunCommandAsync(string ecosystem, string command, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                psi.FileName = "cmd.exe";
                psi.ArgumentList.Add("/C");
                psi.ArgumentList.Add(command);
            }
            else
            {
                psi.FileName = "/bin/sh";
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(command);
            }

            using var process = Process.Start(psi);
            if (process is null)
            {
                _logger.LogWarning("Package manager cache clear: failed to start process for {Ecosystem}", ecosystem);
                return;
            }

            await process.WaitForExitAsync(ct);

            if (process.ExitCode == 0)
                _logger.LogInformation("Package manager cache clear: cleared {Ecosystem} cache", ecosystem);
            else
                _logger.LogWarning("Package manager cache clear: {Ecosystem} exited with code {ExitCode}", ecosystem, process.ExitCode);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Package manager cache clear: error clearing {Ecosystem} cache", ecosystem);
        }
    }
}
