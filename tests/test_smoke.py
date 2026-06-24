from dep_health_scanner import __version__, Ecosystem


def test_imports():
    """Ensure core modules import without errors."""
    assert __version__ is not None


def test_ecosystem_enum():
    """Verify Ecosystem enum has expected members."""
    assert Ecosystem.NPM == "npm"
    assert Ecosystem.CARGO == "cargo"
    assert Ecosystem.PIP == "pip"
    assert Ecosystem.GO == "go"
    assert Ecosystem.UNKNOWN == "unknown"
