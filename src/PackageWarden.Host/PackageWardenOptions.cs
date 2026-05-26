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

namespace PackageWarden.Host;

public class PackageWardenOptions
{
    public string BaseUrl { get; set; } = "http://localhost:5050";
    public StateStoreOptions StateStore { get; set; } = new();
    public KeyValueStoreOptions KeyValueStore { get; set; } = new();
    public KeyValueCacheOptions KeyValueCache { get; set; } = new();
    public PoliciesOptions Policies { get; set; } = new();
    public PackageManagerCacheClearOptions PackageManagerCacheClear { get; set; } = new();
    public string DefaultAction { get; set; } = "Allow";
}

public class StateStoreOptions
{
    public string Provider { get; set; } = "Sqlite";
    public SqliteOptions Sqlite { get; set; } = new();
}

public class SqliteOptions
{
    public string DatabasePath { get; set; } = "package-warden.db";
}

public class KeyValueStoreOptions
{
    public string Provider { get; set; } = "Directory";
    public DirectoryOptions Directory { get; set; } = new();
}

public class KeyValueCacheOptions
{
    public string Provider { get; set; } = "Directory";
    public DirectoryOptions Directory { get; set; } = new();
    public int EvictionIntervalMinutes { get; set; } = 15;
}

public class DirectoryOptions
{
    public string RootPath { get; set; } = "data";
}

public class PoliciesOptions
{
    public string FilePath { get; set; } = "policy.yaml";
    public bool HotReload { get; set; } = false;
}

public class PackageManagerCacheClearOptions
{
    public int IntervalMinutes { get; set; } = 1440;
}