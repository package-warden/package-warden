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

namespace PackageWarden.Core.Policy;

public class PolicyFile
{
    public ScoringConfig Scoring { get; set; } = new();
    public List<PolicyRule> Policies { get; set; } = [];
}

public class ScoringConfig
{
    public string Aggregation { get; set; } = "Sum";
    public SeverityWeights Defaults { get; set; } = new();
    public Dictionary<string, FindingTypeScoring> ByFindingType { get; set; } = [];
}

public class SeverityWeights
{
    public decimal Critical { get; set; } = 50;
    public decimal High { get; set; } = 20;
    public decimal Medium { get; set; } = 5;
    public decimal Low { get; set; } = 1;
    public decimal Info { get; set; } = 0;
}

public class FindingTypeScoring
{
    public bool ScoreFromCvss { get; set; }
    public decimal CvssScale { get; set; } = 10;
    public SeverityWeights? BySeverity { get; set; }
}

public class PolicyRule
{
    public required string Name { get; set; }
    public required string BlockMode { get; set; }
    public required PolicyCondition Conditions { get; set; }
}

public class PolicyCondition
{
    public List<FindingMatcher>? AnyOf { get; set; }
    public CountOfCondition? CountOf { get; set; }
    public ScoreExceedsCondition? ScoreExceeds { get; set; }
    public List<PolicyCondition>? AllOf { get; set; }
    public List<FindingMatcher>? NoneOf { get; set; }
}

public class FindingMatcher
{
    public object? FindingType { get; set; }  // string or list
    public object? Severity { get; set; }     // string or list
    public string? Id { get; set; }
    public string? CvssScore { get; set; }
    public Dictionary<string, string>? Properties { get; set; }
}

public class CountOfCondition
{
    public string? FindingType { get; set; }
    public object? Severity { get; set; }
    public int Threshold { get; set; }
}

public class ScoreExceedsCondition
{
    public decimal Threshold { get; set; }
    public string? FindingType { get; set; }
}