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

using System.Collections.Immutable;

namespace PackageWarden.Core.Domain;

public abstract record Finding
{
    public abstract FindingType Type { get; }
    public abstract string Id { get; }
    public required Severity Severity { get; init; }
    public required string Summary { get; init; }
    public string? Reference { get; init; }
    public IReadOnlyList<string> ReportedBy { get; init; } = [];
    public decimal? AnalyzerScore { get; init; }
    public IReadOnlyDictionary<string, string> Properties { get; init; } =
        ImmutableDictionary<string, string>.Empty;
}

public sealed record VulnerabilityFinding : Finding
{
    public override FindingType Type => FindingType.Vulnerability;
    public override string Id => VulnerabilityId;
    public required string VulnerabilityId { get; init; }
    public string[]? Aliases { get; init; }
    public decimal? CvssScore { get; init; }
    public string? AffectedVersionRange { get; init; }
    public string? FixedVersion { get; init; }
}

public sealed record LicenseFinding : Finding
{
    public override FindingType Type => FindingType.License;
    public override string Id => SpdxId;
    public required string SpdxId { get; init; }
    public required string LicenseName { get; init; }
}

public sealed record MalwareFinding : Finding
{
    public override FindingType Type => FindingType.Malware;
    public override string Id => IndicatorId;
    public required string IndicatorId { get; init; }
    public required string IndicatorType { get; init; }
}

public sealed record DependencyConfusionFinding : Finding
{
    public override FindingType Type => FindingType.DependencyConfusion;
    public override string Id => Namespace is null ? PackageName : $"{Namespace}/{PackageName}";
    public required string PackageName { get; init; }
    public string? Namespace { get; init; }
}

public sealed record SourceRepositoryFinding : Finding
{
    public override FindingType Type => FindingType.SourceRepository;
    public override string Id => PackageIdentifier;
    public required string PackageIdentifier { get; init; }
    public string? RepositoryUrl { get; init; }
}

public sealed record HealthCheckFinding : Finding
{
    public override FindingType Type => FindingType.HealthCheck;
    public override string Id => Source;
    public required string Source { get; init; }
}