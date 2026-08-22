import { useEffect, useRef, useState } from "react";
import { Play } from "lucide-react";
import { FitAddon } from "xterm-addon-fit";
import { Terminal } from "xterm";
import { api } from "../lib/api.js";

const COMMANDS = ["system.health", "dns.config", "route.table", "echo.hash"];

export default function TerminalPanel() {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const [commandId, setCommandId] = useState("system.health");
  const [label, setLabel] = useState("nova-trace");

  useEffect(() => {
    const term = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "SFMono-Regular", Consolas, monospace',
      fontSize: 12,
      theme: {
        background: "#030805",
        foreground: "#7dff9b",
        cursor: "#d2ffd8",
        selectionBackground: "#164b2b",
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(terminalRef.current);
    fit.fit();
    term.writeln("NOVA DIAG TERM :: READY");
    term.writeln("REGISTRY LOCK :: IMMUTABLE");
    xtermRef.current = term;
    const onResize = () => fit.fit();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      term.dispose();
    };
  }, []);

  async function runCommand() {
    const args = commandId === "echo.hash" ? { label } : {};
    xtermRef.current?.writeln(`$ diagnose ${commandId}`);
    try {
      const result = await api.diagnose({ command_id: commandId, args });
      xtermRef.current?.writeln(`exit=${result.exit_code} hash=${result.output_hash}`);
      xtermRef.current?.writeln(result.output);
    } catch (error) {
      xtermRef.current?.writeln(`ERR ${error.message}`);
    }
  }

  return (
    <section className="panel terminal-panel">
      <div className="panel-title">
        <span>DIAGNOSTICS</span>
        <button className="icon-button" onClick={runCommand} title="Run registered command">
          <Play size={15} />
        </button>
      </div>
      <div className="command-row">
        <select value={commandId} onChange={(event) => setCommandId(event.target.value)}>
          {COMMANDS.map((command) => (
            <option key={command}>{command}</option>
          ))}
        </select>
        <input value={label} onChange={(event) => setLabel(event.target.value)} disabled={commandId !== "echo.hash"} />
      </div>
      <div ref={terminalRef} className="xterm-host" />
    </section>
  );
}
