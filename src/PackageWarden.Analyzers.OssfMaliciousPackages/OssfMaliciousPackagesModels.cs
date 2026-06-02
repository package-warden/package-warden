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

using System.Text.Json.Serialization;

namespace PackageWarden.Analyzers.OssfMaliciousPackages;

public class GitHubContentsEntry
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }
}

public class OsvReport
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("summary")]
    public string? Summary { get; set; }

    [JsonPropertyName("details")]
    public string? Details { get; set; }

    [JsonPropertyName("affected")]
    public List<OsvAffected>? Affected { get; set; }

    [JsonPropertyName("references")]
    public List<OsvReference>? References { get; set; }
}

public class OsvAffected
{
    [JsonPropertyName("package")]
    public OsvPackage? Package { get; set; }

    [JsonPropertyName("versions")]
    public List<string>? Versions { get; set; }
}

public class OsvPackage
{
    [JsonPropertyName("ecosystem")]
    public string? Ecosystem { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

public class OsvReference
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }
}

public class OssfCacheResult
{
    public bool InDatabase { get; set; }
    public List<OsvReport>? Reports { get; set; }
}
