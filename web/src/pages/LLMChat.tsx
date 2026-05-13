export function LLMChat() {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>LLM Analyst</h1>
          <p>Local OpenAI-compatible analysis will be attached to scan sessions.</p>
        </div>
      </header>
      <div className="chat-panel">
        <div className="message">No session selected.</div>
        <input placeholder="Ask about a session..." />
      </div>
    </section>
  );
}

