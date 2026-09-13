import json
from pathlib import Path

from typer.testing import CliRunner

from llm_redteam.cli import app

runner = CliRunner()


def _write_contract(path: Path) -> None:
    path.write_text(
        """version: 1
provider: ollama
source: cli-synthetic-inventory
require_local: true
artifacts:
  planner:latest:
    digest: sha256:{planner_digest}
    roles: [red_planner]
  blue:latest:
    digest: sha256:{blue_digest}
    roles: [recommended_model_blue]
""".format(
            planner_digest="a" * 64,
            blue_digest="b" * 64,
        ),
        encoding="utf-8",
    )


def _record(
    model: str,
    digest_char: str,
    *,
    remote_host: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "name": model,
        "model": model,
        "digest": digest_char * 64,
        "size": 4096,
        "details": {
            "format": "gguf",
            "family": "synthetic",
            "parameter_size": "9B",
            "quantization_level": "Q4_K_M",
        },
    }
    if remote_host is not None:
        result["remote_host"] = remote_host
    return result


def _write_inventory(path: Path, *, remote_blue: bool = False) -> None:
    blue = _record(
        "blue:latest",
        "b",
        remote_host="https://ollama.com" if remote_blue else None,
    )
    path.write_text(
        json.dumps(
            {
                "models": [
                    blue,
                    _record("planner:latest", "a"),
                    _record("unrelated:latest", "c"),
                ]
            }
        ),
        encoding="utf-8",
    )


def test_qualify_ollama_inventory_emits_json_report_to_stdout(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts.yaml"
    inventory = tmp_path / "tags.json"
    _write_contract(contracts)
    _write_inventory(inventory)

    result = runner.invoke(
        app,
        [
            "qualify-ollama-inventory",
            "--contracts",
            str(contracts),
            "--inventory",
            str(inventory),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["provider"] == "ollama"
    assert payload["source"] == "cli-synthetic-inventory"
    assert payload["require_local"] is True
    assert len(payload["artifacts"]) == 2
    assert len(payload["inventory_sha256"]) == 64
    assert len(payload["contracts_sha256"]) == 64
    assert len(payload["artifact_set_sha256"]) == 64
    assert len(payload["report_sha256"]) == 64


def test_qualify_ollama_inventory_writes_same_hash_bound_report(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts.yaml"
    inventory = tmp_path / "tags.json"
    output = tmp_path / "qualification-report.json"
    _write_contract(contracts)
    _write_inventory(inventory)

    result = runner.invoke(
        app,
        [
            "qualify-ollama-inventory",
            "--contracts",
            str(contracts),
            "--inventory",
            str(inventory),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["report_sha256"] in result.stdout
    assert "QUALIFIED" in result.stdout
    assert "2 local artifacts" in result.stdout


def test_remote_proxy_fails_without_creating_partial_report(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts.yaml"
    inventory = tmp_path / "tags.json"
    output = tmp_path / "qualification-report.json"
    _write_contract(contracts)
    _write_inventory(inventory, remote_blue=True)

    result = runner.invoke(
        app,
        [
            "qualify-ollama-inventory",
            "--contracts",
            str(contracts),
            "--inventory",
            str(inventory),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert "local model, not remote proxy" in result.output
    assert not output.exists()


def test_missing_inventory_file_fails_without_output(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts.yaml"
    missing_inventory = tmp_path / "missing-tags.json"
    output = tmp_path / "qualification-report.json"
    _write_contract(contracts)

    result = runner.invoke(
        app,
        [
            "qualify-ollama-inventory",
            "--contracts",
            str(contracts),
            "--inventory",
            str(missing_inventory),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert "does not exist" in result.output
    assert not output.exists()
