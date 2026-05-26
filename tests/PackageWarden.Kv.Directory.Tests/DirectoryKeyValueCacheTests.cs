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
using Microsoft.Extensions.Options;
using PackageWarden.Kv.Directory;

namespace PackageWarden.Kv.Directory.Tests;

public class DirectoryKeyValueCacheTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly DirectoryKeyValueCache _cache;

    public DirectoryKeyValueCacheTests()
    {
        var opts = Options.Create(new DirectoryKeyValueCacheOptions { RootPath = _root });
        _cache = new DirectoryKeyValueCache(opts);
    }

    public void Dispose()
    {
        if (System.IO.Directory.Exists(_root))
            System.IO.Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task SetThenGet_ReturnsStoredValue()
    {
        await _cache.SetAsync("pkg:npm:lodash", 42, TimeSpan.FromMinutes(5));
        var entry = await _cache.GetAsync<int>("pkg:npm:lodash");

        entry.Should().NotBeNull();
        entry!.Value.Should().Be(42);
        entry.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Get_MissingKey_ReturnsNull()
    {
        var entry = await _cache.GetAsync<string>("does:not:exist");
        entry.Should().BeNull();
    }

    [Fact]
    public async Task Get_ExpiredEntry_ReturnsNull()
    {
        // TTL in the past makes the entry already expired on write
        await _cache.SetAsync("old:key", "stale", TimeSpan.FromSeconds(-1));
        var entry = await _cache.GetAsync<string>("old:key");

        entry.Should().BeNull();
    }

    [Fact]
    public async Task Get_ExpiredEntry_DeletesFileAsyncInBackground()
    {
        await _cache.SetAsync("old:key2", "stale", TimeSpan.FromSeconds(-1));

        // Locate the file before Get
        var keyPath = Path.Combine(_root, "old", "key2.json");
        File.Exists(keyPath).Should().BeTrue();

        await _cache.GetAsync<string>("old:key2");

        // Fire-and-forget deletion; give it a moment to complete
        await Task.Delay(100);
        File.Exists(keyPath).Should().BeFalse();
    }

    [Fact]
    public async Task Invalidate_RemovesFile()
    {
        await _cache.SetAsync("pkg:nuget:newtonsoft", "data", TimeSpan.FromMinutes(5));
        var keyPath = Path.Combine(_root, "pkg", "nuget", "newtonsoft.json");
        File.Exists(keyPath).Should().BeTrue();

        await _cache.InvalidateAsync("pkg:nuget:newtonsoft");

        File.Exists(keyPath).Should().BeFalse();
    }

    [Fact]
    public async Task InvalidatePrefix_RemovesFilesUnderPrefixDirectory_LeavesOthers()
    {
        // InvalidatePrefixAsync("osv:npm:lodash") maps to _root/osv/npm/lodash.json
        // so GetDirectoryName → _root/osv/npm — only files under that dir are deleted.
        await _cache.SetAsync("osv:npm:lodash:1.0.0", "v1", TimeSpan.FromMinutes(5));
        await _cache.SetAsync("osv:npm:lodash:2.0.0", "v2", TimeSpan.FromMinutes(5));
        await _cache.SetAsync("osv:pypi:requests:1.0.0", "v3", TimeSpan.FromMinutes(5));

        await _cache.InvalidatePrefixAsync("osv:npm:lodash");

        var entry1 = await _cache.GetAsync<string>("osv:npm:lodash:1.0.0");
        var entry2 = await _cache.GetAsync<string>("osv:npm:lodash:2.0.0");
        var entry3 = await _cache.GetAsync<string>("osv:pypi:requests:1.0.0");

        entry1.Should().BeNull();
        entry2.Should().BeNull();
        entry3.Should().NotBeNull("pypi prefix is in a different directory and must not be touched");
    }

    [Fact]
    public async Task Get_CorruptedJsonFile_ReturnsNull()
    {
        // Place a corrupt file at the key path
        var keyPath = Path.Combine(_root, "bad", "key.json");
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        await File.WriteAllTextAsync(keyPath, "{{not valid json}");

        var entry = await _cache.GetAsync<string>("bad:key");

        entry.Should().BeNull("corrupt files should be silently ignored");
    }

    [Fact]
    public async Task Set_OverwritesExistingEntry()
    {
        await _cache.SetAsync("overwrite:key", "first", TimeSpan.FromMinutes(5));
        await _cache.SetAsync("overwrite:key", "second", TimeSpan.FromMinutes(5));

        var entry = await _cache.GetAsync<string>("overwrite:key");
        entry!.Value.Should().Be("second");
    }
}
