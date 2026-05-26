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
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PackageWarden.Kv.Directory;

public class CacheEvictionService : BackgroundService
{
    private readonly string _root;
    private readonly TimeSpan _interval;
    private readonly ILogger<CacheEvictionService> _logger;

    public CacheEvictionService(IOptions<DirectoryKeyValueCacheOptions> opts, ILogger<CacheEvictionService> logger)
    {
        _root = opts.Value.RootPath;
        _interval = TimeSpan.FromMinutes(opts.Value.EvictionIntervalMinutes);
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(_interval, stoppingToken);
            await EvictExpiredAsync(stoppingToken);
        }
    }

    private Task EvictExpiredAsync(CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(_root)) return Task.CompletedTask;

        var evicted = 0;
        foreach (var file in System.IO.Directory.EnumerateFiles(_root, "*.json", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                var json = File.ReadAllText(file);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("expiresAt", out var exp) &&
                    DateTimeOffset.TryParse(exp.GetString(), out var dt) &&
                    dt <= DateTimeOffset.UtcNow)
                {
                    File.Delete(file);
                    evicted++;
                }
            }
            catch { /* ignore individual file errors */ }
        }

        if (evicted > 0)
            _logger.LogDebug("Cache eviction: removed {Count} expired entries", evicted);

        return Task.CompletedTask;
    }
}