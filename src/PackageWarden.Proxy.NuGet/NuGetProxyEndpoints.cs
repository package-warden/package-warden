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

using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Proxy.NuGet;

public static class NuGetProxyEndpoints
{
    public static void MapNuGetProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/nuget/v3");

        // Service index - rewrite resource URLs to point through proxy
        group.MapGet("/index.json", async (
            IOptions<NuGetProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("upstream");
            var response = await http.GetAsync($"{opts.Value.UpstreamBaseUrl}/v3/index.json");
            if (!response.IsSuccessStatusCode) { ctx.Response.StatusCode = (int)response.StatusCode; return; }

            var json = await response.Content.ReadAsStringAsync();
            var proxyBase = $"{ctx.Request.Scheme}://{ctx.Request.Host}/v1/proxy/nuget/v3";
            var upstreamBase = opts.Value.UpstreamBaseUrl;
            var rewritten = RewriteServiceIndex(json, upstreamBase, proxyBase);

            log.LogDebug("[nuget] service-index rewritten for {ProxyBase}", proxyBase);

            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(rewritten);
        });

        // Search endpoint - pass-through
        group.MapGet("/query", async (IOptions<NuGetProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            log.LogDebug("[nuget] passthrough: query{Qs}", ctx.Request.QueryString);
            var qs = ctx.Request.QueryString.Value ?? "";
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/v3/query{qs}");
        });

        // Package registration metadata
        group.MapGet("/registration5/{id}/index.json", async (
            string id,
            IOptions<NuGetProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            log.LogDebug("[nuget] passthrough: registration {Id}", id);
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/v3/registration5/{id}/index.json");
        });

        // Version list
        group.MapGet("/flatcontainer/{id}/index.json", async (
            string id,
            IOptions<NuGetProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            log.LogDebug("[nuget] passthrough: version-list {Id}", id);
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/v3-flatcontainer/{id}/index.json");
        });

        // .nupkg download - policy evaluated
        group.MapGet("/flatcontainer/{id}/{version}/{filename}", async (
            string id, string version, string filename,
            IProxyPipeline pipeline,
            IOptions<NuGetProxyOptions> opts,
            HttpContext ctx) =>
        {
            if (!filename.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
            {
                var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
                log.LogDebug("[nuget] passthrough: flatcontainer {Id} {Version} {Filename}", id, version, filename);
                await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/v3-flatcontainer/{id}/{version}/{filename}");
                return;
            }

            var dl = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            dl.LogDebug("[nuget] download: {Id} {Version}", id, version);

            var upstream = $"{opts.Value.UpstreamBaseUrl}/v3-flatcontainer/{id}/{version}/{filename}";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "nuget",
                PackageName: id,
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });

        // Catch-all: forward any other rewritten /v3/* resource (vulnerabilities, autocomplete, etc.)
        group.MapGet("/{**path}", async (
            string path,
            IOptions<NuGetProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.NuGet");
            log.LogDebug("[nuget] passthrough: {Path}", path);
            var qs = ctx.Request.QueryString.Value ?? "";
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/v3/{path}{qs}");
        });
    }

    private static string RewriteServiceIndex(string json, string upstreamBase, string proxyBase)
    {
        try
        {
            var node = JsonNode.Parse(json);
            var resources = node?["resources"]?.AsArray();
            if (resources is null) return json;

            // NuGet uses several v3-* path prefixes (v3/, v3-flatcontainer/, v3-index/, etc.).
            // Match most-specific first, and require a trailing slash on /v3/ to avoid
            // partial matches against v3-flatcontainer, v3-index, and similar paths.
            // Resources not matching a known proxy path (e.g. v3-index, CDN search) are
            // left pointing at the upstream so the client can reach them directly.
            var flatcontainerUpstream = $"{upstreamBase}/v3-flatcontainer";
            var flatcontainerProxy = $"{proxyBase}/flatcontainer";
            var v3Upstream = $"{upstreamBase}/v3/";

            foreach (var resource in resources)
            {
                var id = resource?["@id"]?.GetValue<string>();
                if (id is null) continue;

                if (id.StartsWith(flatcontainerUpstream, StringComparison.OrdinalIgnoreCase))
                    resource!["@id"] = flatcontainerProxy + id[flatcontainerUpstream.Length..];
                else if (id.StartsWith(v3Upstream, StringComparison.OrdinalIgnoreCase))
                    resource!["@id"] = proxyBase + "/" + id[v3Upstream.Length..];
            }
            return node!.ToJsonString();
        }
        catch
        {
            return json;
        }
    }

    private static async Task PassThrough(HttpContext ctx, string url)
    {
        var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("upstream");
        try
        {
            var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            ctx.Response.StatusCode = (int)response.StatusCode;
            var ct = response.Content.Headers.ContentType?.ToString();
            if (ct is not null) ctx.Response.ContentType = ct;
            await response.Content.CopyToAsync(ctx.Response.Body);
        }
        catch
        {
            ctx.Response.StatusCode = 502;
        }
    }
}