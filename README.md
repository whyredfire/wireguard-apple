# [WireGuard](https://www.wireguard.com/) for macOS

The WireGuard app for macOS.

Tunnels run in a helper that the app installs as a LaunchDaemon on first launch, after asking for an
administrator password. It creates the tunnel interfaces, runs wireguard-go on them and sets up their
routes and DNS, using network code from [Tailscale](https://github.com/tailscale/tailscale). Tunnels
stop when the app quits.

Several tunnels can be active at once. The tunnel list is their priority: a tunnel gets all the traffic
its AllowedIPs cover, except for what a tunnel higher in the list covers, however specific the lower
tunnel's AllowedIPs are. So a tunnel with `0.0.0.0/0` at the top takes all the traffic, and the next
tunnels take over their IPs when it stops. Its DNS servers come first too, and where tunnels' split DNS
has a domain in common, the higher tunnel answers for it. New tunnels go to the bottom
of the list; drag them, or use the arrows below it, to reorder.

## Building

The app builds with SwiftPM and the Xcode Command Line Tools, plus Go for the helper:

```
$ brew install go
$ scripts/build.sh
```

This produces an ad-hoc signed `build/WireGuard.app`. Set `SIGN_IDENTITY` to sign it with a
certificate instead.

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
