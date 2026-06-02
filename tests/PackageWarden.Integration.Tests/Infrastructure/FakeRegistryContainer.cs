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

using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

namespace PackageWarden.Integration.Tests.Infrastructure;

public class FakeRegistryContainer : IAsyncLifetime
{
    private IContainer? _container;

    public string BaseUrl { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        var fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures");

        _container = new ContainerBuilder("nginx:alpine")
            .WithPortBinding(80, true)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "nginx.conf")),
                "/etc/nginx/conf.d/default.conf")
            // shared
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "dummy.bin")),
                "/usr/share/nginx/html/dummy.bin")
            // npm
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "npm", "test-package.json")),
                "/usr/share/nginx/html/test-package.json")
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "npm", "tarball.tgz")),
                "/usr/share/nginx/html/tarball.tgz")
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "npm", "scoped-test-package.json")),
                "/usr/share/nginx/html/npm-scoped-test-package.json")
            // nuget
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "nuget", "v3-index.json")),
                "/usr/share/nginx/html/nuget-v3-index.json")
            // pypi
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "pypi", "simple-test-package.html")),
                "/usr/share/nginx/html/pypi-simple-test-package.html")
            // maven
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "maven", "test-package-1.0.0.pom")),
                "/usr/share/nginx/html/maven-test-package-1.0.0.pom")
            // gem
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "gem", "test-gem.json")),
                "/usr/share/nginx/html/gem-test-gem.json")
            // golang
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(fixtures, "golang", "v1.0.0.info")),
                "/usr/share/nginx/html/golang-v1.0.0.info")
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(80).ForPath("/health")))
            .Build();

        await _container.StartAsync();
        BaseUrl = $"http://localhost:{_container.GetMappedPublicPort(80)}";
    }

    public async Task DisposeAsync()
    {
        if (_container is not null)
            await _container.DisposeAsync();
    }
}