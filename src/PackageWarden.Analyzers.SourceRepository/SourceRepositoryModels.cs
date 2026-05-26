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

namespace PackageWarden.Analyzers.SourceRepository;

// npm registry
internal class NpmPackageInfo
{
    [JsonPropertyName("repository")]
    public NpmRepository? Repository { get; set; }
}

internal class NpmRepository
{
    [JsonPropertyName("url")]
    public string? Url { get; set; }
}

// PyPI
internal class PyPiPackageInfo
{
    [JsonPropertyName("info")]
    public PyPiInfo? Info { get; set; }
}

internal class PyPiInfo
{
    [JsonPropertyName("home_page")]
    public string? HomePage { get; set; }

    [JsonPropertyName("project_urls")]
    public Dictionary<string, string>? ProjectUrls { get; set; }
}

// crates.io
internal class CargoPackageInfo
{
    [JsonPropertyName("crate")]
    public CargoCrate? Crate { get; set; }
}

internal class CargoCrate
{
    [JsonPropertyName("repository")]
    public string? Repository { get; set; }
}

// RubyGems
internal class GemPackageInfo
{
    [JsonPropertyName("source_code_uri")]
    public string? SourceCodeUri { get; set; }

    [JsonPropertyName("homepage_uri")]
    public string? HomepageUri { get; set; }
}

// GitHub releases
internal class GitHubRelease
{
    [JsonPropertyName("tag_name")]
    public string? TagName { get; set; }

    [JsonPropertyName("prerelease")]
    public bool Prerelease { get; set; }
}

// GitHub tags
internal class GitHubTag
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
