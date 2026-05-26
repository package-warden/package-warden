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

namespace PackageWarden.Core.Policy;

public static class PredicateParser
{
    public static bool EvaluateString(string? expression, string? value)
    {
        if (expression is null) return true;
        if (value is null) return false;

        expression = expression.Trim();

        if (expression.StartsWith("in [") && expression.EndsWith("]"))
        {
            var list = expression[4..^1]
                .Split(',')
                .Select(s => s.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return list.Contains(value);
        }

        if (expression.StartsWith("contains ", StringComparison.OrdinalIgnoreCase))
        {
            var text = expression[9..].Trim();
            return value.Contains(text, StringComparison.OrdinalIgnoreCase);
        }

        if (expression.StartsWith("= "))
        {
            return string.Equals(value, expression[2..].Trim(), StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(value, expression, StringComparison.OrdinalIgnoreCase);
    }

    public static bool EvaluateNumeric(string? expression, decimal? value)
    {
        if (expression is null) return true;
        if (value is null) return false;

        expression = expression.Trim();

        if (expression.StartsWith(">= ") && decimal.TryParse(expression[3..], out var gte))
            return value >= gte;
        if (expression.StartsWith("> ") && decimal.TryParse(expression[2..], out var gt))
            return value > gt;
        if (expression.StartsWith("<= ") && decimal.TryParse(expression[3..], out var lte))
            return value <= lte;
        if (expression.StartsWith("< ") && decimal.TryParse(expression[2..], out var lt))
            return value < lt;
        if (expression.StartsWith("= ") && decimal.TryParse(expression[2..], out var eq))
            return value == eq;
        if (decimal.TryParse(expression, out var direct))
            return value == direct;

        return false;
    }
}