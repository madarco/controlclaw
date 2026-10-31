
const TRANSCRIPT_KIND = {"user":"rounded-xl bg-bg px-4 py-3 sm:ml-[10%]","status":"border-l-2 border-brand pl-3 font-mono text-[12px] text-ink-2"};
function renderTranscriptEvent(item, names) {
  let node;
  if (item.kind === "tool_call" || item.kind === "tool_result") {
    node = document.createElement("details");
    node.className = "mb-4 min-w-0 rounded-lg border border-line";
    const title = document.createElement("summary");
    title.className = "cursor-pointer px-3 py-2.5 font-mono text-[12px] text-ink-2";
    title.textContent = item.title || names[item.kind];
    const pre = document.createElement("pre");
    pre.className = "m-0 max-h-80 overflow-auto border-t border-line p-4 font-mono text-[12px] leading-[1.7] text-ink";
    pre.textContent = item.text;
    node.append(title, pre);
  } else {
    node = document.createElement("div");
    node.className = "mb-5 whitespace-pre-wrap text-[14px] leading-[1.6] text-ink [overflow-wrap:anywhere] " + (TRANSCRIPT_KIND[item.kind] || "");
    const label = document.createElement("span");
    label.className = "mb-1.5 block font-mono text-[11px] tracking-[0.04em] text-ink-2 uppercase";
    label.textContent = item.title || names[item.kind] || item.kind;
    node.append(label, document.createTextNode(item.text));
  }
  return node;
}
