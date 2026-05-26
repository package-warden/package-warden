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

public record RequestQuery(
    DateTimeOffset? From,
    DateTimeOffset? To,
    string? Ecosystem,
    string? PackageName,
    bool? Blocked,
    int Page = 1,
    int PageSize = 50);

public record ExceptionQuery(bool? Active = null, int Page = 1, int PageSize = 50);

public record PagedResult<T>(
    IReadOnlyList<T> Items,
    int TotalCount,
    int Page,
    int PageSize)
{
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
}

public record SystemStats(
    int TotalRequests,
    int BlockedRequests,
    int AllowedRequests,
    IReadOnlyList<EcosystemStats> ByEcosystem);

public record EcosystemStats(
    string Ecosystem,
    int TotalRequests,
    int BlockedRequests);