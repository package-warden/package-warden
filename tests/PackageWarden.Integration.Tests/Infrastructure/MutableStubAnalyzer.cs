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

using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Integration.Tests.Infrastructure;

/// <summary>
/// Analyzer whose findings can be mutated between requests within the same
/// factory instance. Registered as a singleton so the mutation is visible to
/// all subsequent pipeline invocations.
/// </summary>
public class MutableStubAnalyzer : IPackageAnalyzer
{
    private volatile IReadOnlyList<Finding> _findings;

    public string Name => "MutableStub";

    public MutableStubAnalyzer(IReadOnlyList<Finding> initialFindings)
    {
        _findings = initialFindings;
    }

    public void SetFindings(IReadOnlyList<Finding> findings) => _findings = findings;

    public Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default)
        => Task.FromResult(new AnalyzerResult(Name, _findings));
}
