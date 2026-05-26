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

using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PackageWarden.Kv.Directory;

namespace PackageWarden.Kv.Directory.Tests;

public class CacheEvictionServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (System.IO.Directory.Exists(_root))
            System.IO.Directory.Delete(_root, recursive: true);
    }

    private CacheEvictionService CreateService()
    {
        var opts = Options.Create(new DirectoryKeyValueCacheOptions
        {
            RootPath = _root,
            EvictionIntervalMinutes = 0   // zero delay → runs immediately on each iteration
        });
        return new CacheEvictionService(opts, NullLogger<CacheEvictionService>.Instance);
    }

    private void WriteEnvelope(string filename, DateTimeOffset expiresAt, string value = "v")
    {
        var path = Path.Combine(_root, filename);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, $$$"""{"value":"{{{value}}}","expiresAt":"{{{expiresAt:O}}}"}""");
    }

    [Fact]
    public async Task EvictsExpiredFiles_LeavesValidFiles()
    {
        System.IO.Directory.CreateDirectory(_root);
        WriteEnvelope("expired.json", DateTimeOffset.UtcNow.AddHours(-1));
        WriteEnvelope("valid.json", DateTimeOffset.UtcNow.AddHours(1));

        using var service = CreateService();
        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(200);
        await service.StopAsync(CancellationToken.None);

        File.Exists(Path.Combine(_root, "expired.json")).Should().BeFalse("expired entry must be evicted");
        File.Exists(Path.Combine(_root, "valid.json")).Should().BeTrue("non-expired entry must be kept");
    }

    [Fact]
    public async Task MultipleExpiredFiles_AllEvicted()
    {
        System.IO.Directory.CreateDirectory(_root);
        WriteEnvelope("a.json", DateTimeOffset.UtcNow.AddMinutes(-10));
        WriteEnvelope("b.json", DateTimeOffset.UtcNow.AddMinutes(-5));
        WriteEnvelope("c.json", DateTimeOffset.UtcNow.AddMinutes(-1));

        using var service = CreateService();
        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(200);
        await service.StopAsync(CancellationToken.None);

        System.IO.Directory.GetFiles(_root, "*.json").Should().BeEmpty();
    }

    [Fact]
    public async Task MissingDirectory_DoesNotThrow()
    {
        // Root directory does not exist — service must start and stop cleanly
        System.IO.Directory.Exists(_root).Should().BeFalse();

        using var service = CreateService();
        using var cts = new CancellationTokenSource();

        var act = async () =>
        {
            await service.StartAsync(cts.Token);
            await Task.Delay(100);
            await service.StopAsync(CancellationToken.None);
        };

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task CorruptJsonFile_DoesNotStopEviction()
    {
        System.IO.Directory.CreateDirectory(_root);
        // Corrupt file — should be skipped without aborting the loop
        File.WriteAllText(Path.Combine(_root, "corrupt.json"), "not-json");
        WriteEnvelope("expired.json", DateTimeOffset.UtcNow.AddHours(-1));

        using var service = CreateService();
        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(200);
        await service.StopAsync(CancellationToken.None);

        // The expired valid entry must still be evicted even though a corrupt file exists
        File.Exists(Path.Combine(_root, "expired.json")).Should().BeFalse();
    }
}
