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

namespace PackageWarden.Analyzers.OsvDev;

public class OsvBatchRequest
{
    [JsonPropertyName("queries")]
    public List<OsvQuery> Queries { get; set; } = [];
}

public class OsvQuery
{
    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("package")]
    public OsvPackage Package { get; set; } = new();
}

public class OsvPackage
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("ecosystem")]
    public string Ecosystem { get; set; } = "";
}

public class OsvBatchResponse
{
    [JsonPropertyName("results")]
    public List<OsvQueryResult> Results { get; set; } = [];
}

public class OsvQueryResult
{
    [JsonPropertyName("vulns")]
    public List<OsvVulnerability>? Vulns { get; set; }
}

public class OsvVulnerability
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("aliases")]
    public List<string>? Aliases { get; set; }

    [JsonPropertyName("summary")]
    public string? Summary { get; set; }

    [JsonPropertyName("details")]
    public string? Details { get; set; }

    [JsonPropertyName("references")]
    public List<OsvReference>? References { get; set; }

    [JsonPropertyName("severity")]
    public List<OsvSeverity>? Severity { get; set; }

    [JsonPropertyName("affected")]
    public List<OsvAffected>? Affected { get; set; }
}

public class OsvReference
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }
}

public class OsvSeverity
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("score")]
    public string? Score { get; set; }
}

public class OsvAffected
{
    [JsonPropertyName("ranges")]
    public List<OsvRange>? Ranges { get; set; }
}

public class OsvRange
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("events")]
    public List<OsvEvent>? Events { get; set; }
}

public class OsvEvent
{
    [JsonPropertyName("introduced")]
    public string? Introduced { get; set; }

    [JsonPropertyName("fixed")]
    public string? Fixed { get; set; }
}