# l2split

**Pick any app — send it straight out the Ethernet, bypassing the VPN. An
alternative split tunneling.**

Per-application L2 split via a pure NDIS light filter driver.

l2split is **per application** — app identity (PID via TCP table) is decided in
user-space, per-frame decisions are made at the Ethernet (L2) layer.

**How it works** (no WFP, no Winsock hooking):

1. A kernel static filter rule (dst-MAC = VPN gateway, direction TX) holds only
   frames heading to the VPN — every other frame keeps flowing purely in-kernel.
2. The user-mode engine reads those held frames, tests IPv4/TCP/UDP, and finds
   the connection owner via `GetExtendedTcpTable` (source port → PID → exe).
3. Whitelisted app → the frame's dst-MAC is rewritten to the LAN gateway and
   injected to the LAN adapter → traffic exits directly to the internet.
4. Other apps → injected back unchanged → they keep using the VPN.

## Setup (once per machine)

The installer ships a WHQL-signed NDIS filter driver — no test signing, no
Secure Boot changes, works on stock Windows 10/11:

```
1. run l2split setup.exe
2. if the driver is missing, the built-in wizard asks once — press
   "Install driver" and approve the UAC prompt
3. restart once if asked — done
```

## Teardown

In the app: remove the driver via the wizard/setup menu, or run the bundled
MSI's uninstaller.

## Notes

- Only packets of apps you whitelist leave the VPN tunnel; everything else is
  untouched and stays in the tunnel.
- Legal: use only on machines you own or are authorized to manage.
