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

using System.Text.Json;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Kv.Directory;

public class DirectoryKeyValueCache : IKeyValueCache
{
    private readonly string _root;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public DirectoryKeyValueCache(IOptions<DirectoryKeyValueCacheOptions> opts)
    {
        _root = opts.Value.RootPath;
        System.IO.Directory.CreateDirectory(_root);
    }

    public async Task<CacheEntry<T>?> GetAsync<T>(string key, CancellationToken ct = default)
    {
        var path = KeyToPath(key);
        if (!File.Exists(path)) return null;

        try
        {
            await using var fs = File.OpenRead(path);
            var envelope = await JsonSerializer.DeserializeAsync<CacheEnvelope<T>>(fs, JsonOpts, ct);
            if (envelope is null) return null;

            if (envelope.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                _ = Task.Run(() => TryDelete(path), CancellationToken.None);
                return null;
            }

            return new CacheEntry<T>(envelope.Value, envelope.ExpiresAt);
        }
        catch
        {
            return null;
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan ttl, CancellationToken ct = default)
    {
        var path = KeyToPath(key);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var envelope = new CacheEnvelope<T>(value, DateTimeOffset.UtcNow.Add(ttl));
        await using var fs = File.Create(path);
        await JsonSerializer.SerializeAsync(fs, envelope, JsonOpts, ct);
    }

    public Task InvalidateAsync(string key, CancellationToken ct = default)
    {
        TryDelete(KeyToPath(key));
        return Task.CompletedTask;
    }

    public Task InvalidatePrefixAsync(string prefix, CancellationToken ct = default)
    {
        var prefixPath = KeyToPath(prefix);
        var dir = Path.GetDirectoryName(prefixPath) ?? _root;
        if (!System.IO.Directory.Exists(dir)) return Task.CompletedTask;

        foreach (var file in System.IO.Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories))
            TryDelete(file);

        return Task.CompletedTask;
    }

    private string KeyToPath(string key)
    {
        var relative = key.Replace(':', Path.DirectorySeparatorChar)
                          .Replace('/', Path.DirectorySeparatorChar);
        return Path.Combine(_root, relative + ".json");
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { /* best effort */ }
    }

    private record CacheEnvelope<T>(T Value, DateTimeOffset ExpiresAt);
}