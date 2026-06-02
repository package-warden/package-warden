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

using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Proxy.Npm;

public static class NpmProxyEndpoints
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    public static void MapNpmProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/npm");

        // Scoped package manifest
        group.MapGet("/@{scope}/{name}", async (
            string scope, string name,
            IOptions<NpmProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Npm");
            log.LogDebug("[npm] manifest: @{Scope}/{Name}", scope, name);
            var upstream = $"{opts.Value.UpstreamBaseUrl}/@{scope}/{name}";
            await ServeManifestAsync(ctx, upstream, opts.Value.UpstreamBaseUrl);
        });

        // Unscoped package manifest — also handles %2f-encoded scoped names (@scope%2fname)
        group.MapGet("/{name}", async (
            string name,
            IOptions<NpmProxyOptions> opts,
            HttpContext ctx) =>
        {
            // ASP.NET Core does not decode %2f in route parameters; do it explicitly.
            // A bare @scope with no package name is not a valid request.
            var decodedName = Uri.UnescapeDataString(name);
            if (decodedName.StartsWith('@') && !decodedName.Contains('/')) return;
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Npm");
            log.LogDebug("[npm] manifest: {Name}", decodedName);
            var upstream = $"{opts.Value.UpstreamBaseUrl}/{decodedName}";
            await ServeManifestAsync(ctx, upstream, opts.Value.UpstreamBaseUrl);
        });

        // Scoped tarball download
        group.MapGet("/@{scope}/{name}/-/{filename}", async (
            string scope, string name, string filename,
            IProxyPipeline pipeline,
            IOptions<NpmProxyOptions> opts,
            HttpContext ctx) =>
        {
            var version = ExtractVersionFromFilename(filename);
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Npm");
            log.LogDebug("[npm] download: @{Scope}/{Name} {Version}", scope, name, version);
            var upstream = $"{opts.Value.UpstreamBaseUrl}/@{scope}/{name}/-/{filename}";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "npm",
                PackageName: $"@{scope}/{name}",
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });

        // Unscoped tarball download — also handles %2f-encoded scoped names (@scope%2fname)
        group.MapGet("/{name}/-/{filename}", async (
            string name, string filename,
            IProxyPipeline pipeline,
            IOptions<NpmProxyOptions> opts,
            HttpContext ctx) =>
        {
            var decodedName = Uri.UnescapeDataString(name);
            var version = ExtractVersionFromFilename(filename);
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Npm");
            log.LogDebug("[npm] download: {Name} {Version}", decodedName, version);
            var upstream = $"{opts.Value.UpstreamBaseUrl}/{decodedName}/-/{filename}";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "npm",
                PackageName: decodedName,
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });
    }

    private static async Task ServeManifestAsync(
        HttpContext ctx,
        string upstreamUrl,
        string upstreamBase)
    {
        // Fetch, rewrite tarball URLs, then serve
        var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("upstream");
        HttpResponseMessage response;
        try
        {
            response = await http.GetAsync(upstreamUrl);
        }
        catch
        {
            ctx.Response.StatusCode = 502;
            return;
        }

        if (!response.IsSuccessStatusCode)
        {
            ctx.Response.StatusCode = (int)response.StatusCode;
            return;
        }

        var json = await response.Content.ReadAsStringAsync();
        var proxyBase = $"{ctx.Request.Scheme}://{ctx.Request.Host}/v1/proxy/npm";
        var rewritten = RewriteTarballUrls(json, upstreamBase, proxyBase);

        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(rewritten);
    }

    private static string RewriteTarballUrls(string json, string upstreamBase, string proxyBase)
    {
        return json.Replace(upstreamBase, proxyBase);
    }

    private static string? ExtractVersionFromFilename(string filename)
    {
        // e.g. "express-4.18.2.tgz" -> "4.18.2"
        var match = Regex.Match(filename, @"-(\d[\d.\-a-zA-Z]*)\.tgz$");
        return match.Success ? match.Groups[1].Value : null;
    }
}