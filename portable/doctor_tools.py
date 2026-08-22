"""Print availability of the audited security tools on this host."""
from tool_registry import TOOL_REGISTRY, tool_available

for command_id, spec in sorted(TOOL_REGISTRY.items()):
    needs = ",".join(spec.host_binaries) if spec.host_binaries else "-"
    print(f"{command_id:<26} {spec.kind:<8} available={str(tool_available(spec)):<5} needs={needs}")
