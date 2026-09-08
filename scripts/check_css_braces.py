import pathlib

path = pathlib.Path("static/dashboard.css")
text = path.read_text(encoding="utf-8")
print("open", text.count("{"), "close", text.count("}"))

lines = text.splitlines()
stack = []  # store (line_num, line_text) for each '{'
bad = None
for i, l in enumerate(lines, 1):
    opens = l.count("{")
    closes = l.count("}")
    # push opens
    for _ in range(opens):
        stack.append((i, l))
    # pop closes
    for _ in range(closes):
        if stack:
            stack.pop()
        elif bad is None:
            bad = i

if bad:
    print("negative at", bad)
    start = max(1, bad - 8)
    end = min(len(lines), bad + 8)
    print("--- context ---")
    for li in range(start, end + 1):
        prefix = "->" if li == bad else "  "
        print(f"{prefix} {li:04d}: {lines[li-1]}")

print("unmatched opens at end", len(stack))
if stack:
    print("--- unmatched openings ---")
    for ln, l in stack[-10:]:
        print(f"line {ln}: {l}")
