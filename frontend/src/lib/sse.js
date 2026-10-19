// Server-Sent Event parsing, kept free of browser globals so it can be verified
// independently of the app shell.

export function drainSseFrames(buffer, onEvent) {
  let frameEnd;
  while ((frameEnd = buffer.indexOf("\n\n")) !== -1) {
    const frame = buffer.slice(0, frameEnd);
    buffer = buffer.slice(frameEnd + 2);

    let event = "message";
    let raw = "";
    for (const line of frame.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) raw += line.slice(5).trim();
    }

    let data = {};
    try {
      data = raw ? JSON.parse(raw) : {};
    } catch {
      data = { raw };
    }
    if (onEvent) onEvent({ event, data });
  }
  return buffer;
}

export async function consumeSseStream(body, onEvent) {
  if (!body) throw new Error("stream body missing");
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    buffer = drainSseFrames(buffer, onEvent);
  }

  // A final frame may arrive without the trailing blank line.
  if (buffer.trim()) drainSseFrames(`${buffer}\n\n`, onEvent);
}
