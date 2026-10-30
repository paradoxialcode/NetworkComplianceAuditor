import pytest

from auditor.compliance.operators import MISSING, OPERATORS, validate_operand


@pytest.mark.parametrize(
    ("op", "actual", "expected", "result"),
    [
        ("eq", 2, 2, True),
        ("eq", 2, 3, False),
        ("eq", False, False, True),
        ("eq", 0, False, False),
        ("eq", True, 1, False),
        ("eq", "2", 2, False),
        ("ne", "a", "b", True),
        ("gt", 5, 4, True),
        ("gte", 8, 8, True),
        ("lt", 3, 4, True),
        ("lte", 5, 4, False),
        ("in", "v2", ["v1", "v2"], True),
        ("not_in", "v1", ["v2"], True),
        ("contains", "ssh-rsa key", "rsa", True),
        ("contains", ["a", "b"], "b", True),
        ("regex", "aes256-cbc", r"^aes(128|256)", True),
        ("regex", "des", r"^aes", False),
        ("present", 0, None, True),
        ("present", MISSING, None, False),
        ("present", None, None, False),
        ("absent", MISSING, None, True),
        ("absent", "x", None, False),
    ],
)
def test_operator_results(op, actual, expected, result):
    assert OPERATORS[op](actual, expected) is result


@pytest.mark.parametrize(
    ("op", "actual", "expected"),
    [
        ("gte", "8", 8),
        ("gt", True, 0),
        ("lt", None, 1),
        ("regex", 5, "x"),
        ("contains", 5, "x"),
        ("contains", "abc", 5),
    ],
)
def test_operator_type_errors(op, actual, expected):
    with pytest.raises(TypeError):
        OPERATORS[op](actual, expected)


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("nope", 1),
        ("eq", None),
        ("present", 1),
        ("gte", "8"),
        ("gte", True),
        ("in", "scalar"),
        ("in", []),
        ("regex", "(unclosed"),
        ("regex", "a" * 300),
        ("regex", "(a|aa)+$"),
        ("regex", 5),
    ],
)
def test_validate_operand_rejects(op, value):
    with pytest.raises(ValueError):
        validate_operand(op, value)


@pytest.mark.parametrize(
    ("op", "value"),
    [("eq", False), ("eq", 0), ("in", ["a"]), ("regex", "^a"), ("absent", None), ("gte", 1.5)],
)
def test_validate_operand_accepts(op, value):
    validate_operand(op, value)
