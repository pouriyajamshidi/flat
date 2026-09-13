# Demo GIF for the README. Record it from the project root:
#   vhs .images/flat.tape
# Needs passwordless sudo, curl, dig, and an interface with internet access.

Output .images/flat.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1260
Set Height 700
Set Padding 20
Set Margin 20
Set MarginFill "#181825"
Set WindowBar Colorful
Set BorderRadius 10
Set TypingSpeed 50ms
Set Framerate 24

# Build flat and send some TCP (HTTPS) and UDP (DNS) traffic to 1.1.1.1 in the background.
# Filtering on 1.1.1.1 keeps other traffic on the machine out of the recording.
Hide
Type "export PS1='> '" Enter
Type "make >/dev/null 2>&1" Enter
Wait@2m
Type "(while true; do curl -4 -s -o /dev/null https://1.1.1.1; dig +short @1.1.1.1 example.com; sleep 1; done) >/dev/null 2>&1 &" Enter
Type "clear" Enter
Sleep 500ms
Show

Type "sudo ./flat -i wlp3s0 -ip 1.1.1.1"
Sleep 800ms
Enter
Sleep 14s
Ctrl+C
Sleep 3s

Hide
Type "kill %1" Enter
