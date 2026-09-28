# Status

A sign on maki's screen, big enough to read across the room: Available, Busy, On a call, In a
meeting, Do not disturb, Focusing, Away, Lunch or BRB. Left and right go through them; the centre
turns the screen light, to be noticed. The letters are Cantarell ExtraBold (SIL Open Font
License 1.1) at three sizes, drawn once by `assets/font.py` into `src/font.rs`; the app picks the
biggest the sign fits in, over up to four lines.

Software on your computer can set it too (the app asks for the link permission), through maki
desktop's local socket, a line of JSON each way. The message is the text to show (printable
ASCII, up to 40 characters, answered `ok`), or the name of one of the signs, which picks it; an
empty message asks what's showing. From a shell, when a call starts, say:

```sh
maki-status() {
  python3 - "$1" <<'EOF'
import base64, json, os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(f"{os.environ.get('XDG_RUNTIME_DIR', '/tmp')}/maki-{os.getuid()}.sock")
text = base64.b64encode(sys.argv[1].encode()).decode()
s.sendall(json.dumps({"id": 1, "type": "appMessage", "app": "com.leviathan.maki.status", "data": text}).encode() + b"\n")
answer = json.loads(s.makefile().readline())
print(base64.b64decode(answer["data"]).decode() if answer.get("ok") else answer["error"])
EOF
}
maki-status "On a call"    # one of its signs: ok
maki-status "Back at 3"    # any text: ok
maki-status ""             # what's showing: Back at 3
```

If Status isn't open, maki starts it out of sight to answer, as long as no other app is open,
and shows what was set the next time it's opened.
