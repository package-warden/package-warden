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

public record PackageException
{
    public Guid ExceptionId { get; init; }
    public required string Ecosystem { get; init; }
    public required string PackageName { get; init; }
    public string? PackageVersion { get; init; }
    public DateTimeOffset GrantedAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
    public bool IsActive => RevokedAt is null;
    public Guid? GrantedForRequestId { get; init; }
    // Composite finding IDs recorded at grant time: "{FindingType}:{Finding.Id}"
    // Exception only applies when current findings are a subset of these IDs.
    public IReadOnlyList<string> FindingIds { get; init; } = [];
    public string? Notes { get; init; }
}
