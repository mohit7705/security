from pathlib import Path

from security_analyzer.core.nuclei_templates import resolve_nuclei_templates


def test_resolves_templates_from_standard_home_location(tmp_path, monkeypatch):
    home = tmp_path / "home"
    templates = home / ".local" / "nuclei-templates"
    templates.mkdir(parents=True)
    (templates / "example.yaml").write_text("id: example\\n", encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)

    assert resolve_nuclei_templates({}, project_root=tmp_path) == templates.resolve()


def test_explicit_invalid_directory_does_not_silently_fallback(tmp_path, monkeypatch):
    home_templates = tmp_path / "home" / "nuclei-templates"
    home_templates.mkdir(parents=True)
    (home_templates / "example.yaml").write_text("id: example\\n", encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)

    result = resolve_nuclei_templates(
        {"templates_dir": "missing-templates"},
        project_root=tmp_path,
    )
    assert result is None


def test_ignores_non_template_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    templates = home / "nuclei-templates"
    templates.mkdir(parents=True)
    (templates / "README.md").write_text("not a template", encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)

    assert resolve_nuclei_templates({}, project_root=tmp_path) is None


def test_resolves_environment_override(tmp_path, monkeypatch):
    templates = tmp_path / "custom-templates"
    templates.mkdir()
    (templates / "custom.yml").write_text("id: custom\\n", encoding="utf-8")
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(templates))

    assert resolve_nuclei_templates({}, project_root=tmp_path) == templates.resolve()


def test_resolves_relative_config_from_project_root(tmp_path, monkeypatch):
    templates = tmp_path / "vendor" / "nuclei"
    templates.mkdir(parents=True)
    (templates / "custom.yaml").write_text("id: custom\\n", encoding="utf-8")
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)

    assert resolve_nuclei_templates(
        {"templates_dir": "vendor/nuclei"},
        project_root=tmp_path,
    ) == templates.resolve()
