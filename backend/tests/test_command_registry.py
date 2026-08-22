from command_registry import COMMAND_REGISTRY, CommandRegistryError, execute_registered_command, validate_command


def test_registry_is_not_empty():
    assert "system.health" in COMMAND_REGISTRY


def test_rejects_unknown_command():
    try:
        validate_command("rm-anything", {}, "admin")
    except CommandRegistryError as exc:
        assert "Unknown" in str(exc)
    else:
        raise AssertionError("unknown command was accepted")


def test_executes_mock_command():
    result = execute_registered_command("echo.hash", {"label": "nova"}, "admin")
    assert result["exit_code"] == 0
    assert result["output_hash"]
    assert "label_hash" in result["output"]
