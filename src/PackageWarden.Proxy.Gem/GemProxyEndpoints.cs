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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Proxy.Gem;

public static class GemProxyEndpoints
{
    public static void MapGemProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/gem");

        // Full index spec files (used by `bundle install --full-index`)
        group.MapGet("/specs.4.8.gz", async (IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: specs.4.8.gz");
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/specs.4.8.gz");
        });

        group.MapGet("/latest_specs.4.8.gz", async (IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: latest_specs.4.8.gz");
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/latest_specs.4.8.gz");
        });

        group.MapGet("/prerelease_specs.4.8.gz", async (IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: prerelease_specs.4.8.gz");
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/prerelease_specs.4.8.gz");
        });

        // Compact index (default Bundler mode)
        group.MapGet("/versions", async (IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: versions");
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/versions");
        });

        group.MapGet("/info/{name}", async (string name, IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: info/{Name}", name);
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/info/{name}");
        });

        // Bundler dependencies API
        group.MapGet("/api/v1/dependencies", async (IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: api/v1/dependencies{Qs}", ctx.Request.QueryString);
            var qs = ctx.Request.QueryString.Value ?? "";
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/api/v1/dependencies{qs}");
        });

        // Gem metadata
        group.MapGet("/api/v1/gems/{name}.json", async (
            string name, IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: api/v1/gems/{Name}.json", name);
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/api/v1/gems/{name}.json");
        });

        // Gemspec
        group.MapGet("/quick/Marshal.4.8/{filename}", async (
            string filename, IOptions<GemProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] passthrough: quick/{Filename}", filename);
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/quick/Marshal.4.8/{filename}");
        });

        // Gem download - policy evaluated
        group.MapGet("/gems/{filename}", async (
            string filename,
            IProxyPipeline pipeline,
            IOptions<GemProxyOptions> opts,
            HttpContext ctx) =>
        {
            var (name, version) = ParseGemFilename(filename);
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Gem");
            log.LogDebug("[gem] download: {Name} {Version}", name, version);
            var upstream = $"{opts.Value.UpstreamBaseUrl}/gems/{filename}";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "gem",
                PackageName: name,
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });
    }

    private static (string name, string? version) ParseGemFilename(string filename)
    {
        // e.g. "rails-7.0.4.gem"
        if (filename.EndsWith(".gem")) filename = filename[..^4];
        var lastDash = filename.LastIndexOf('-');
        if (lastDash > 0)
            return (filename[..lastDash], filename[(lastDash + 1)..]);
        return (filename, null);
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