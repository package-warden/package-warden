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
using PackageWarden.Core.Interfaces;
using PackageWarden.Core.Pipeline;
using PackageWarden.Core.Policy;

namespace PackageWarden.Core.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddStateStore<T>(this IServiceCollection services)
        where T : class, IStateStore
    {
        services.AddSingleton<IStateStore, T>();
        return services;
    }

    public static IServiceCollection AddKeyValueStore<T>(this IServiceCollection services)
        where T : class, IKeyValueStore
    {
        services.AddSingleton<IKeyValueStore, T>();
        return services;
    }

    public static IServiceCollection AddKeyValueCache<T>(this IServiceCollection services)
        where T : class, IKeyValueCache
    {
        services.AddSingleton<IKeyValueCache, T>();
        return services;
    }

    public static IServiceCollection AddPackageAnalyzer<T>(this IServiceCollection services)
        where T : class, IPackageAnalyzer
    {
        services.AddSingleton<IPackageAnalyzer, T>();
        return services;
    }

    public static IServiceCollection AddProxyPipeline(this IServiceCollection services)
    {
        services.AddSingleton<IFindingAggregator, FindingAggregator>();
        services.AddSingleton<IProxyPipeline, ProxyPipeline>();
        return services;
    }
}