"""Gates for skill routing inside the LAU brain.

The brain must treat registry skills as first-class tools: a bare skill name, a
'run <skill> <target>' phrase, or a skills query should route to the skill
tools, while ordinary prompts keep flowing to the normal verb table.
"""

from nova_core.brain import NovaBrain


def _brain():
    return NovaBrain.__new__(NovaBrain)


def test_explicit_run_skill_with_target():
    brain = _brain()
    actions = brain._parse_skill_intent("run nmap 10.0.0.5", "run nmap 10.0.0.5")
    assert actions == [{"tool": "skill", "params": {"key": "nmap", "target": "10.0.0.5"}}]


def test_skill_url_target():
    brain = _brain()
    actions = brain._parse_skill_intent(
        "run nuclei https://example.test", "run nuclei https://example.test"
    )
    assert actions[0]["params"]["key"] == "nuclei"
    assert actions[0]["params"]["target"] == "https://example.test"


def test_bare_skill_name_routes():
    brain = _brain()
    actions = brain._parse_skill_intent("sherlock alupoa9", "sherlock alupoa9")
    assert actions is not None
    assert actions[0]["params"]["key"] == "sherlock"
    assert actions[0]["params"]["target"] == "alupoa9"


def test_skills_catalog_phrase():
    brain = _brain()
    assert brain._parse_skill_intent("list skills", "list skills") == [
        {"tool": "skill_catalog", "params": {}}
    ]


def test_unrelated_prompt_is_not_a_skill():
    brain = _brain()
    assert brain._parse_skill_intent("what can you do", "what can you do") is None
    assert brain._parse_skill_intent("run a port scan", "run a port scan") is None
