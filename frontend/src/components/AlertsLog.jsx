export default function AlertsLog({ events }) {
  return (
    <footer className="panel alerts-log">
      <div className="panel-title">
        <span>ALERTS_LOGS</span>
        <code>{events.length.toString().padStart(3, "0")}</code>
      </div>
      <div className="log-stream">
        {events.map((event, index) => (
          <div className="log-line" key={`${event.level}-${index}`}>
            <span>{event.level}</span>
            <code>{event.text}</code>
          </div>
        ))}
      </div>
    </footer>
  );
}
