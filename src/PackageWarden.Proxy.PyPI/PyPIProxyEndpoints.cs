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

namespace PackageWarden.Proxy.PyPI;

public static class PyPIProxyEndpoints
{
    public static void MapPyPIProxy(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/proxy/pypi");

        // Package index
        group.MapGet("/simple/", async (IOptions<PyPIProxyOptions> opts, HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.PyPI");
            log.LogDebug("[pypi] passthrough: simple/");
            await PassThrough(ctx, $"{opts.Value.UpstreamBaseUrl}/simple/");
        });

        // Per-package file list - rewrite download URLs
        group.MapGet("/simple/{name}/", async (
            string name,
            IOptions<PyPIProxyOptions> opts,
            HttpContext ctx) =>
        {
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.PyPI");
            log.LogDebug("[pypi] simple: {Name}", name);
            var http = ctx.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient("upstream");
            var response = await http.GetAsync($"{opts.Value.UpstreamBaseUrl}/simple/{name}/");
            if (!response.IsSuccessStatusCode) { ctx.Response.StatusCode = (int)response.StatusCode; return; }

            var html = await response.Content.ReadAsStringAsync();
            var proxyBase = $"{ctx.Request.Scheme}://{ctx.Request.Host}/v1/proxy/pypi";
            // Package files are served from files.pythonhosted.org, not pypi.org.
            // Both hosts must be rewritten so pip routes downloads through the proxy.
            var rewritten = html
                .Replace(opts.Value.FilesBaseUrl, proxyBase)
                .Replace(opts.Value.UpstreamBaseUrl, proxyBase);

            ctx.Response.ContentType = response.Content.Headers.ContentType?.ToString() ?? "text/html";
            await ctx.Response.WriteAsync(rewritten);
        });

        // File download - policy evaluated
        group.MapGet("/packages/{**path}", async (
            string path,
            IProxyPipeline pipeline,
            IOptions<PyPIProxyOptions> opts,
            HttpContext ctx) =>
        {
            var filename = Path.GetFileName(path);
            var (packageName, version) = ExtractNameAndVersion(filename);
            var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PackageWarden.Proxy.PyPI");
            log.LogDebug("[pypi] download: {PackageName} {Version}", packageName, version);

            var upstream = $"{opts.Value.FilesBaseUrl}/packages/{path}";
            await pipeline.HandleAsync(new ProxyPipelineRequest(
                Ecosystem: "pypi",
                PackageName: packageName,
                PackageVersion: version,
                UpstreamUrl: upstream,
                HttpContext: ctx,
                EvaluatePolicy: true));
        });
    }

    private static (string name, string? version) ExtractNameAndVersion(string filename)
    {
        // e.g. "requests-2.28.0.tar.gz", "my-pkg-1.0.0-py3-none-any.whl"
        // Name ends at the first '-'-separated segment that starts with a digit (PEP 440 version).
        var noExt = Path.GetFileNameWithoutExtension(filename);
        if (noExt.EndsWith(".tar")) noExt = Path.GetFileNameWithoutExtension(noExt);
        var parts = noExt.Split('-');
        for (var i = 1; i < parts.Length; i++)
        {
            if (parts[i].Length > 0 && char.IsDigit(parts[i][0]))
                return (string.Join("-", parts[..i]), parts[i]);
        }
        return (parts[0], parts.Length > 1 ? parts[1] : null);
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