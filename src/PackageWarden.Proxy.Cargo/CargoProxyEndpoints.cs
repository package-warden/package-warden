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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Proxy.Cargo;

public static class CargoProxyEndpoints
{
    public static void MapCargoProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/cargo");

        // Crate download - policy evaluated
        group.MapGet("/api/v1/crates/{name}/{version}/download", async (
            string name, string version,
            IProxyPipeline pipeline,
            IOptions<CargoProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Cargo");
            log.LogDebug("[cargo] download: {Name} {Version}", name, version);

            // crates.io sparse registry dl template: {base}/crates/{crate}/{version}/download
            var upstream = $"{opts.Value.UpstreamDownloadUrl}/crates/{name}/{version}/download";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "cargo",
                PackageName: name,
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });

        // Registry config - rewrite the dl URL template so Cargo downloads through this proxy
        group.MapGet("/config.json", async (
            IOptions<CargoProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Cargo");
            var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("upstream");
            var response = await http.GetAsync($"{opts.Value.UpstreamIndexUrl}/config.json");
            if (!response.IsSuccessStatusCode) { ctx.Response.StatusCode = (int)response.StatusCode; return; }

            var json = await response.Content.ReadAsStringAsync();
            var proxyBase = $"{ctx.Request.Scheme}://{ctx.Request.Host}/v1/proxy/cargo";
            var rewritten = RewriteCargoConfig(json, proxyBase);

            log.LogDebug("[cargo] config.json upstream: {Json}", json);
            log.LogDebug("[cargo] config.json rewritten: {Rewritten}", rewritten);

            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(rewritten);
        });

        // Sparse registry index entry
        group.MapGet("/{**path}", async (
            string path,
            IOptions<CargoProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Cargo");
            log.LogDebug("[cargo] index passthrough: {Path}", path);
            await PassThrough(ctx, $"{opts.Value.UpstreamIndexUrl}/{path}");
        });
    }

    private static string RewriteCargoConfig(string json, string proxyBase)
    {
        try
        {
            var node = JsonNode.Parse(json);
            if (node?["dl"] is JsonNode dlNode)
            {
                var dl = dlNode.GetValue<string>();
                var templateStart = dl.IndexOf('{');
                if (templateStart >= 0)
                    // Has template variables: preserve them, replace only the base.
                    node["dl"] = $"{proxyBase}/api/v1/crates/{dl[templateStart..]}";
                else
                    // No template variables (e.g. "https://static.crates.io/crates"): Cargo
                    // would append /{name}/{version}/download itself — inject explicit template
                    // variables so all downloads route through the proxy instead.
                    node["dl"] = $"{proxyBase}/api/v1/crates/{{crate}}/{{version}}/download";
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