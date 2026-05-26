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

namespace PackageWarden.Proxy.Golang;

public static class GolangProxyEndpoints
{
    public static void MapGolangProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/golang");

        // Module zip download - policy evaluated
        group.MapGet("/{**path}", async (
            string path,
            IProxyPipeline pipeline,
            IOptions<GolangProxyOptions> opts,
            HttpContext ctx) =>
        {
            var upstream = $"{opts.Value.UpstreamBaseUrl}/{path}";
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Golang");

            if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var (module, version) = ParseGoModulePath(path);
                log.LogDebug("[golang] download: {Module} {Version}", module, version);
                await pipeline.HandleAsync(new ProxyPipelineRequest(
                    Ecosystem: "golang",
                    PackageName: module,
                    PackageVersion: version,
                    UpstreamUrl: upstream,
                    HttpContext: ctx,
                    EvaluatePolicy: true));
            }
            else
            {
                log.LogDebug("[golang] passthrough: {Path}", path);
                await PassThrough(ctx, upstream);
            }
        });
    }

    private static (string module, string? version) ParseGoModulePath(string path)
    {
        // e.g. "github.com/pkg/errors/@v/v0.9.0.zip"
        var atv = path.IndexOf("/@v/", StringComparison.Ordinal);
        if (atv < 0) return (path, null);
        var module = path[..atv];
        var rest = path[(atv + 4)..]; // strip "/@v/"
        var version = rest.EndsWith(".zip") ? rest[..^4] : rest;
        return (module, version);
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