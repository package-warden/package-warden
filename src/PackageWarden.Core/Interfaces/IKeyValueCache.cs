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

namespace PackageWarden.Core.Interfaces;

public interface IKeyValueCache
{
    Task<CacheEntry<T>?> GetAsync<T>(string key, CancellationToken ct = default);
    Task SetAsync<T>(string key, T value, TimeSpan ttl, CancellationToken ct = default);
    Task InvalidateAsync(string key, CancellationToken ct = default);
    Task InvalidatePrefixAsync(string prefix, CancellationToken ct = default);
}

public record CacheEntry<T>(T Value, DateTimeOffset ExpiresAt);