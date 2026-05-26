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

namespace PackageWarden.Proxy.Maven;

public static class MavenProxyEndpoints
{
    private static readonly HashSet<string> BinaryExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".jar", ".aar", ".war", ".ear" };

    public static void MapMavenProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/maven");

        group.MapGet("/{**path}", async (
            string path,
            IProxyPipeline pipeline,
            IOptions<MavenProxyOptions> opts,
            HttpContext ctx) =>
        {
            var upstream = $"{opts.Value.UpstreamBaseUrl}/{path}";
            var ext = Path.GetExtension(path);
            var evaluatePolicy = BinaryExtensions.Contains(ext);

            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.Maven");

            if (evaluatePolicy)
            {
                var (packageName, version) = ParseMavenPath(path);
                log.LogDebug("[maven] download: {PackageName} {Version}", packageName, version);
                await pipeline.HandleAsync(new ProxyPipelineRequest(
                    Ecosystem: "maven",
                    PackageName: packageName,
                    PackageVersion: version,
                    UpstreamUrl: upstream,
                    HttpContext: ctx,
                    EvaluatePolicy: true));
            }
            else
            {
                log.LogDebug("[maven] passthrough: {Path}", path);
                await PassThrough(ctx, upstream);
            }
        });
    }

    private static (string packageName, string? version) ParseMavenPath(string path)
    {
        // path: {group}/{artifact}/{version}/{file}
        var parts = path.Split('/');
        if (parts.Length >= 3)
        {
            var artifact = parts[^3];
            var version = parts[^2];
            var groupId = string.Join(".", parts[..^3]);
            return ($"{groupId}:{artifact}", version);
        }
        return (path, null);
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