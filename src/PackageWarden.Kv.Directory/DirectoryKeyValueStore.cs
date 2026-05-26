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

using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Kv.Directory;

public class DirectoryKeyValueStore : IKeyValueStore
{
    private readonly string _root;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public DirectoryKeyValueStore(IOptions<DirectoryKeyValueStoreOptions> opts)
    {
        _root = opts.Value.RootPath;
        System.IO.Directory.CreateDirectory(_root);
    }

    public async Task<T?> GetAsync<T>(string key, CancellationToken ct = default)
    {
        var path = KeyToPath(key);
        if (!File.Exists(path)) return default;
        await using var fs = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<T>(fs, JsonOpts, ct);
    }

    public async Task SetAsync<T>(string key, T value, CancellationToken ct = default)
    {
        var path = KeyToPath(key);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using var fs = File.Create(path);
        await JsonSerializer.SerializeAsync(fs, value, JsonOpts, ct);
    }

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var path = KeyToPath(key);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
    {
        return Task.FromResult(File.Exists(KeyToPath(key)));
    }

    public async IAsyncEnumerable<string> ListKeysAsync(string prefix, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var prefixPath = KeyToPath(prefix);
        var dir = Path.GetDirectoryName(prefixPath) ?? _root;
        if (!System.IO.Directory.Exists(dir)) yield break;

        foreach (var file in System.IO.Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories))
        {
            var key = PathToKey(file);
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                yield return key;
        }

        await Task.CompletedTask;
    }

    private string KeyToPath(string key)
    {
        var relative = key.Replace(':', Path.DirectorySeparatorChar)
                          .Replace('/', Path.DirectorySeparatorChar);
        return Path.Combine(_root, relative + ".json");
    }

    private string PathToKey(string path)
    {
        var relative = Path.GetRelativePath(_root, path);
        if (relative.EndsWith(".json")) relative = relative[..^5];
        return relative.Replace(Path.DirectorySeparatorChar, ':');
    }
}