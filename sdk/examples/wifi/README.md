# Wi-Fi

Your Wi-Fi networks as QR codes, for guests: phones join a network by scanning maki's screen (the
`WIFI:T:WPA;S:name;P:password;;` text that routers' stickers and phones' share screens hold). Up
to eight, kept in the app's storage on maki; left and right go through them.

Add one from the menu's "Scan a network" (the camera permission): point maki at a router's
sticker or another phone's share screen. Or send one from the computer (the link permission),
through maki desktop's local socket, a line of JSON each way, as
[Status's README](../status/README.md) shows: the message is the `WIFI:` text, answered `ok` (or
why not); an empty message asks which networks maki has, a name a line.

The menu also shows the password as text, for typing it in by hand, and forgets the network
showing.
