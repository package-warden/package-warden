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

using FluentAssertions;
using PackageWarden.Core.Policy;

namespace PackageWarden.Core.Tests.Policy;

public class PredicateParserTests
{
    // ---- EvaluateString ----

    [Fact]
    public void EvaluateString_NullExpression_ReturnsTrue()
        => PredicateParser.EvaluateString(null, "anything").Should().BeTrue();

    [Fact]
    public void EvaluateString_NullValue_ReturnsFalse()
        => PredicateParser.EvaluateString("something", null).Should().BeFalse();

    [Fact]
    public void EvaluateString_BothNull_ReturnsTrue()
        => PredicateParser.EvaluateString(null, null).Should().BeTrue();

    [Fact]
    public void EvaluateString_InList_Match_ReturnsTrue()
        => PredicateParser.EvaluateString("in [foo, bar, baz]", "bar").Should().BeTrue();

    [Fact]
    public void EvaluateString_InList_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateString("in [foo, bar]", "qux").Should().BeFalse();

    [Fact]
    public void EvaluateString_InList_CaseInsensitive()
        => PredicateParser.EvaluateString("in [FOO, BAR]", "foo").Should().BeTrue();

    [Fact]
    public void EvaluateString_Contains_Match_ReturnsTrue()
        => PredicateParser.EvaluateString("contains hello", "say hello world").Should().BeTrue();

    [Fact]
    public void EvaluateString_Contains_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateString("contains xyz", "say hello world").Should().BeFalse();

    [Fact]
    public void EvaluateString_Contains_CaseInsensitive()
        => PredicateParser.EvaluateString("contains HELLO", "say hello world").Should().BeTrue();

    [Fact]
    public void EvaluateString_EqualPrefix_Match_ReturnsTrue()
        => PredicateParser.EvaluateString("= exact", "exact").Should().BeTrue();

    [Fact]
    public void EvaluateString_EqualPrefix_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateString("= exact", "notexact").Should().BeFalse();

    [Fact]
    public void EvaluateString_EqualPrefix_CaseInsensitive()
        => PredicateParser.EvaluateString("= EXACT", "exact").Should().BeTrue();

    [Fact]
    public void EvaluateString_DirectEquality_Match_ReturnsTrue()
        => PredicateParser.EvaluateString("hello", "hello").Should().BeTrue();

    [Fact]
    public void EvaluateString_DirectEquality_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateString("hello", "world").Should().BeFalse();

    [Fact]
    public void EvaluateString_DirectEquality_CaseInsensitive()
        => PredicateParser.EvaluateString("HELLO", "hello").Should().BeTrue();

    // ---- EvaluateNumeric ----

    [Fact]
    public void EvaluateNumeric_NullExpression_ReturnsTrue()
        => PredicateParser.EvaluateNumeric(null, 5m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_NullValue_ReturnsFalse()
        => PredicateParser.EvaluateNumeric(">= 5", null).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_BothNull_ReturnsTrue()
        => PredicateParser.EvaluateNumeric(null, null).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_GreaterThanOrEqual_Above_ReturnsTrue()
        => PredicateParser.EvaluateNumeric(">= 5.0", 5.1m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_GreaterThanOrEqual_Equal_ReturnsTrue()
        => PredicateParser.EvaluateNumeric(">= 5.0", 5.0m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_GreaterThanOrEqual_Below_ReturnsFalse()
        => PredicateParser.EvaluateNumeric(">= 5.0", 4.9m).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_GreaterThan_Above_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("> 5.0", 5.1m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_GreaterThan_Equal_ReturnsFalse()
        => PredicateParser.EvaluateNumeric("> 5.0", 5.0m).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_LessThanOrEqual_Below_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("<= 5.0", 4.9m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_LessThanOrEqual_Equal_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("<= 5.0", 5.0m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_LessThan_Above_ReturnsFalse()
        => PredicateParser.EvaluateNumeric("< 5.0", 5.1m).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_LessThan_Below_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("< 5.0", 4.9m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_Equal_Match_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("= 7.5", 7.5m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_Equal_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateNumeric("= 7.5", 7.6m).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_DirectNumber_Match_ReturnsTrue()
        => PredicateParser.EvaluateNumeric("9.8", 9.8m).Should().BeTrue();

    [Fact]
    public void EvaluateNumeric_DirectNumber_NoMatch_ReturnsFalse()
        => PredicateParser.EvaluateNumeric("9.8", 9.7m).Should().BeFalse();

    [Fact]
    public void EvaluateNumeric_UnrecognisedExpression_ReturnsFalse()
        => PredicateParser.EvaluateNumeric("not-a-number", 5m).Should().BeFalse();
}
