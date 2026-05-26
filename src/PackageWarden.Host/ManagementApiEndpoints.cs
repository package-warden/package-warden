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

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Host;

file record GrantExceptionRequest(Guid RequestId, string? Notes);

public static class ManagementApiEndpoints
{
    public static void MapManagementApi(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1");

        // Stats
        group.MapGet("/stats", async (IStateStore store, HttpContext ctx) =>
        {
            var stats = await store.GetStatsAsync();
            return Results.Ok(stats);
        });

        // Request log
        group.MapGet("/requests", async (
            IStateStore store,
            DateTimeOffset? from,
            DateTimeOffset? to,
            string? ecosystem,
            string? packageName,
            bool? blocked,
            int page = 1,
            int pageSize = 50) =>
        {
            var query = new RequestQuery(from, to, ecosystem, packageName, blocked, page, pageSize);
            var result = await store.QueryRequestsAsync(query);
            return Results.Ok(result);
        });

        // Single request
        group.MapGet("/requests/{id:guid}", async (Guid id, IStateStore store) =>
        {
            var req = await store.GetRequestAsync(id);
            return req is null ? Results.NotFound() : Results.Ok(req);
        });

        // Grant exception from a blocked request
        group.MapPost("/exceptions", async (GrantExceptionRequest body, IStateStore store) =>
        {
            var req = await store.GetRequestAsync(body.RequestId);
            if (req is null) return Results.NotFound(new { error = "request_not_found" });
            if (!req.Blocked) return Results.BadRequest(new { error = "request_not_blocked" });
            if (req.Findings.Count == 0) return Results.BadRequest(new { error = "no_findings_to_except" });

            var findingIds = req.Findings.Select(f => $"{f.Type}:{f.Id}").ToList();
            var exception = new PackageException
            {
                ExceptionId = Guid.NewGuid(),
                Ecosystem = req.Ecosystem,
                PackageName = req.PackageName,
                PackageVersion = req.PackageVersion,
                GrantedAt = DateTimeOffset.UtcNow,
                GrantedForRequestId = req.RequestId,
                FindingIds = findingIds,
                Notes = body.Notes
            };
            await store.CreateExceptionAsync(exception);
            return Results.Created($"/api/v1/exceptions/{exception.ExceptionId}", exception);
        });

        // List exceptions
        group.MapGet("/exceptions", async (IStateStore store, bool? active, int page = 1, int pageSize = 50) =>
        {
            var query = new ExceptionQuery(active, page, pageSize);
            var result = await store.QueryExceptionsAsync(query);
            return Results.Ok(result);
        });

        // Revoke exception
        group.MapDelete("/exceptions/{id:guid}", async (Guid id, IStateStore store) =>
        {
            await store.RevokeExceptionAsync(id);
            return Results.NoContent();
        });

        // System status
        group.MapGet("/system/status", () =>
        {
            return Results.Ok(new
            {
                status = "ok",
                timestamp = DateTimeOffset.UtcNow
            });
        });

        // System info
        group.MapGet("/system/info", (ServerPaths paths) =>
        {
            return Results.Ok(new
            {
                appSettingsPath = paths.AppSettingsPath,
                policyFilePath = paths.PolicyFilePath,
                dataDirectory = paths.DataDirectory
            });
        });
    }
}