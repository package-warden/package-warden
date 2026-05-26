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

namespace PackageWarden.Core.Domain;

public record ProxyRequest
{
    public Guid RequestId { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public required string Ecosystem { get; init; }
    public required string PackageName { get; init; }
    public string? PackageVersion { get; init; }
    public required string UpstreamUrl { get; init; }
    public required string ClientIp { get; init; }
    public bool Blocked { get; set; }
    public string? BlockReason { get; set; }
    public PolicyBlockMode? BlockMode { get; set; }
    public int? MatchedCount { get; set; }
    public int? Threshold { get; set; }
    public decimal? RiskScoreThreshold { get; set; }
    public IReadOnlyList<Finding> Findings { get; set; } = [];
    public PackageRiskScore? RiskScore { get; set; }
    public TimeSpan Duration { get; set; }
}