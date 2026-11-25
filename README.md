# DragonGuard

A Windows service + tray app that protects against BadUSB / "rubber ducky" keyboards, malicious mice, rogue USB network
adapters (LAN Turtle, PoisonTap, Bash Bunny, P4wnP1) and malicious pendrives.

## What it does
* **New keyboard → it can't type until you approve it.** The service switches it off at once; the tray agent locks all
  keyboard input and switches it back on only so you can enter the arrow sequence. An approval window shows a random sequence
  of 6 arrow keys. Press them in order on any connected keyboard (the new one or your existing one) to allow it; this also works when it's the PC's first and only
  keyboard. Click **Block device** to block it. Esc does not block a pending keyboard (the device could press Esc itself and
  cut off the capture), it is just recorded; Esc only blocks when the pending device is a mouse that froze all mouse input.
* **Captures what the device tried to type.** Blocked keystrokes are shown in the window, for example `[WIN+R]powershell -w h ...[ENTER]`.
* **Detects automated typing.** Typing faster than about 30 ms per key is flagged as keystroke injection, and arrow approval is
  then disabled for that connection.
* **New mouse / touch screen / pen → switched off until you approve it**, so it can't click or move the cursor. Your other
  mice keep working. If a pointer can't be switched off, all mouse input is frozen instead and you approve with the arrow
  keys. Blocked clicks and cursor jumps are shown, and jumps straight to fixed screen positions raise a warning.
* **New USB network adapter → switched off until you approve it.** This also works on the lock screen and before logon, which
  is exactly when the "steal the password hash from a locked PC" attack happens.
* **New USB drive → approval window and drive scan.** It shows the contents of any `autorun.inf` (including `open=` /
  `shellexecute=` lines) and lists executables and scripts, shortcuts in the drive root, hidden executables and double
  extensions (`photo.jpg.exe`). Drives from allowed devices are scanned too, and you get a tray warning if something is suspicious.
* One window per *physical* device, so a gadget that is keyboard + network + storage at once is shown as one device and flagged.
* **Block** disables the whole device and puts it on the block list. The service switches it off again every time it's
  plugged in, at any time, including before logon.
* Brute-force protection: a wrong arrow key creates a new sequence and starts a 2 s cooldown (30 s after every 5th failure).

## How it runs
DragonGuard installs as a **Windows service** (`UsbGuard`, LocalSystem, automatic start, restarts itself if it crashes) plus a
**tray agent** in every logged-on session.

* **Service:** works from boot, on the lock screen and before logon. It watches HID, network and disk devices, switches off
  new keyboards, mice/pointers and USB network adapters until you approve them, and switches blocked devices off again
  whenever they're plugged in. It owns the device list and the log.
* **Tray agent:** the service starts it in each session, elevated, without a UAC prompt (for standard users it runs as SYSTEM
  in their session, and admin-only menu items are hidden). It shows the approval windows and runs the keyboard/mouse hooks.
  * For a new keyboard it locks all typing first, then asks the service to switch that keyboard on so you can enter the
    arrow sequence.
  * When you lock the PC, a keyboard that's waiting for approval is switched off again.
* **Connection:** the two parts talk through the named pipe `\\.\pipe\UsbGuard`. Only SYSTEM and Administrators can open it,
  and the agent checks that the pipe is served by the installed exe, so a fake server can't take over.
* **First-keyboard rule:** if nobody is logged on and there's no trusted keyboard (no built-in or allowed one), a new keyboard
  is left on so you can log in. The approval window appears right after login and you approve it with the arrows.
* **If the service is unreachable,** the agent still locks input and does Allow/Block itself.

## Name, icon and logo
The app is shown as **DragonGuard** (tray, windows, service display name, file description). The icon and the approval-window
logo are built from `logo.jpg`: run `powershell -ExecutionPolicy Bypass -File tools\make-assets.ps1` after changing it
(writes `assets\DragonGuard.ico` and `assets\logo.png`, which `build.cmd` embeds). Internal names stay `UsbGuard`
(service name, pipe, `C:\Program Files\UsbGuard`, `%ProgramData%\UsbGuard`, exe name), so existing installs update in place
and keep their device lists.

## Install / update / uninstall
```
build.cmd                        # uses the C# compiler that ships with Windows, no SDK needed
bin\UsbGuard.exe                 # double-click: offers to install (or update) the service
bin\UsbGuard.exe --install       # same, scripted (add --quiet to skip the message box)
"C:\Program Files\UsbGuard\UsbGuard.exe" --uninstall
```
The exe is copied to `C:\Program Files\UsbGuard\`, which only admins can write to, so the service binary can't be swapped.
You can also uninstall from the tray menu. On the first service start, the keyboards, mice, USB network adapters and USB drives
connected at that moment are trusted. Data is kept in `%ProgramData%\UsbGuard\` (`devices.cfg`, `usbguard.log`, `*.state`).
Uninstalling keeps these files.

## Tray menu
* Event log, allowed/blocked device list (only admins can change it), and a test approval window.
* **Disable Windows AutoRun / AutoPlay.**
* **Windows policy: refuse to install new USB network adapters.** Windows Device Installation Restrictions deny RNDIS /
  CDC-ECM / NCM / EEM interfaces. Adapters connected when you switch it on stay allowed. While it's on, new USB Ethernet
  dongles and phone tethering won't install; switch it off temporarily to add one.
* **Network hardening.** LLMNR, NetBIOS broadcasts and WinHTTP WPAD off; SMB client signing required; the firewall blocks all
  inbound connections on Public / unidentified networks. The original values are restored when you switch it off. A reboot
  is recommended.
* **Uninstall DragonGuard.**

## Limitations
* This is not a filter driver. Devices are switched off as soon as Windows reports them, which in practice happens before an
  attack device acts (they usually wait 0.5–2 s, and a network adapter needs seconds for DHCP). A device that acts within
  milliseconds of being plugged in could in theory get its first keys or clicks through.
* While a keyboard is waiting for approval, **every** keyboard is blocked, including your trusted one. You can use the mouse
  and the arrow keys.
* On the lock screen, the UAC secure desktop and before logon, new keyboards, mice and network adapters are kept switched off
  by the service, but keystrokes can't be captured or shown there (the hooks only run on the user's desktop).
* Windows doesn't let some keyboards be switched off, including many wireless receivers (for example the Dell Universal
  Receiver). It reports these as "not disableable" (`CR_NOT_DISABLEABLE`, 0x28). While such a keyboard is waiting for
  approval, only the input lock stops it, so on the lock screen and before logon it isn't stopped at all. **Block** removes
  it the way "Safely remove hardware" does and keeps it off until it's unplugged. It's removed again whenever it's plugged
  back in. To use it again after you allow it in the device list, unplug it and plug it back in.
* An approval for a keyboard can only be completed on the physical console session, not over RDP.
* Covered: USB and Bluetooth keyboards, mice and digitizers; USB mass storage; USB network adapters. Built-in (ACPI/I2C/PCI)
  and virtual devices are ignored. HID "consumer control" keys (media/launch keys) are not filtered.
* Network hardening covers WinHTTP's WPAD; the per-user "Automatically detect settings" proxy option in Windows settings is
  separate. Restricting outgoing NTLM (`RestrictSendingNTLMTraffic`) is the next step if you don't need old NAS/SMB servers.
