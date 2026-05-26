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

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Integration.Tests.Infrastructure;

public class PackageWardenFactory : WebApplicationFactory<Program>
{
    private readonly string _fakeBaseUrl;
    private readonly string _tempDir;

    public string? PolicyFilePath { get; init; }
    public IPackageAnalyzer? ExtraAnalyzer { get; init; }
    public string EnabledEcosystem { get; init; } = "npm";

    public PackageWardenFactory(string fakeBaseUrl)
    {
        _fakeBaseUrl = fakeBaseUrl;
        _tempDir = Path.Combine(Path.GetTempPath(), $"pw-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var policyPath = PolicyFilePath ?? Path.Combine(_tempDir, "nonexistent.yaml");

        var config = new Dictionary<string, string?>
        {
            ["PackageWarden:Proxies:Npm:Enabled"] = "false",
            ["PackageWarden:Proxies:NuGet:Enabled"] = "false",
            ["PackageWarden:Proxies:PyPI:Enabled"] = "false",
            ["PackageWarden:Proxies:Maven:Enabled"] = "false",
            ["PackageWarden:Proxies:Cargo:Enabled"] = "false",
            ["PackageWarden:Proxies:Gem:Enabled"] = "false",
            ["PackageWarden:Proxies:Golang:Enabled"] = "false",
            ["PackageWarden:Analyzers:OsvDev:Enabled"] = "false",
            ["PackageWarden:Analyzers:SourceRepository:Enabled"] = "false",
            ["PackageWarden:StateStore:Sqlite:DatabasePath"] = Path.Combine(_tempDir, "pw.db"),
            ["PackageWarden:KeyValueStore:Directory:RootPath"] = Path.Combine(_tempDir, "kv-store"),
            ["PackageWarden:KeyValueCache:Directory:RootPath"] = Path.Combine(_tempDir, "kv-cache"),
            ["PackageWarden:Policies:FilePath"] = policyPath,
        };

        switch (EnabledEcosystem.ToLowerInvariant())
        {
            case "npm":
                config["PackageWarden:Proxies:Npm:Enabled"] = "true";
                config["PackageWarden:Proxies:Npm:UpstreamBaseUrl"] = _fakeBaseUrl;
                break;
            case "nuget":
                config["PackageWarden:Proxies:NuGet:Enabled"] = "true";
                config["PackageWarden:Proxies:NuGet:UpstreamBaseUrl"] = _fakeBaseUrl;
                break;
            case "pypi":
                config["PackageWarden:Proxies:PyPI:Enabled"] = "true";
                config["PackageWarden:Proxies:PyPI:UpstreamBaseUrl"] = _fakeBaseUrl;
                config["PackageWarden:Proxies:PyPI:FilesBaseUrl"] = _fakeBaseUrl;
                break;
            case "maven":
                config["PackageWarden:Proxies:Maven:Enabled"] = "true";
                config["PackageWarden:Proxies:Maven:UpstreamBaseUrl"] = _fakeBaseUrl;
                break;
            case "cargo":
                config["PackageWarden:Proxies:Cargo:Enabled"] = "true";
                config["PackageWarden:Proxies:Cargo:UpstreamIndexUrl"] = _fakeBaseUrl;
                config["PackageWarden:Proxies:Cargo:UpstreamDownloadUrl"] = _fakeBaseUrl;
                break;
            case "gem":
                config["PackageWarden:Proxies:Gem:Enabled"] = "true";
                config["PackageWarden:Proxies:Gem:UpstreamBaseUrl"] = _fakeBaseUrl;
                break;
            case "golang":
                config["PackageWarden:Proxies:Golang:Enabled"] = "true";
                config["PackageWarden:Proxies:Golang:UpstreamBaseUrl"] = _fakeBaseUrl;
                break;
        }

        builder.ConfigureAppConfiguration((_, cfg) => cfg.AddInMemoryCollection(config));

        builder.ConfigureServices(services =>
        {
            if (ExtraAnalyzer is not null)
                services.AddSingleton<IPackageAnalyzer>(ExtraAnalyzer);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_tempDir))
        {
            try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }
    }
}