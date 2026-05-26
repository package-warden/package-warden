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

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace PackageWarden.Core.Policy;

public static class PolicyFileLoader
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static PolicyFile Load(string path)
    {
        var yaml = File.ReadAllText(path);
        return Deserializer.Deserialize<PolicyFile>(yaml);
    }

    public static PolicyFile LoadFromString(string yaml)
    {
        return Deserializer.Deserialize<PolicyFile>(yaml);
    }
}