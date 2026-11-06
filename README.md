# l2split

**Pick any app — send it straight out the Ethernet, bypassing the VPN. An
alternative split tunneling.**

Per-application L2 split via NDIS light filter — VPN split tunneling
per-aplikasi atas driver NDIS murni (`NDISLWF.sys`, proyek
[ndislwf](https://github.com/obvirm/ndislwf)).

l2split memang **per aplikasi** — identitas app (PID via TCP table) ditentukan di
user-space, keputusan dibuat di frame Ethernet (L2).

**Cara kerja** (tanpa WFP, tanpa Winsock hooking):

1. Kernel rule (`POLICY`, match dst-MAC gateway VPN) memblokir frame TX
   menuju VPN — frame tetap jatuh ke ring TX untuk dilihat user-mode.
2. Engine user-mode membaca ring, menguji frame IPv4/TCP/UDP, dan cari
   pemilik koneksi lewat `GetExtendedTcpTable` (port sumber → PID → exe).
3. App masuk whitelist → dst-MAC frame ditulis ulang ke gateway LAN + inject
   (jalur inject kernel memanggil `NdisFSendNetBufferLists` langsung — tidak
   kena rule blok lagi) → frame keluar langsung ke internet tanpa VPN.
4. App lain → inject apa adanya → tetap lewat VPN.

## Setup sekali (tiap mesin)

Driver yang tidak disertifikasi produksi hanya load saat *test signing*
aktif. Tombolnya dijalankan sekali per mesin:

```
1. copy ndislwf.inf / ndislwf.sys / ndislwf.cat (hasil build ndislwf)
   ke folder driver\
2. driver\driver.cmd  →  pilih 3 (testsigning ON)  →  reboot
3. driver\driver.cmd  →  pilih 1 (install driver)
4. jalankan l2split
```

## Teardown

```
driver\driver.cmd  →  pilih 2 (lepas driver)
driver\driver.cmd  →  pilih 4 (testsigning off)  →  reboot
```

## Catatan

- `driver\driver.cmd` self-elevate (UAC) otomatis.
- Watermark "Test Mode" muncul di pojok desktop selama testsigning ON —
  normal, hilang saat tombol dimatikan (pilihan 4).
- Secure Boot tidak mengizinkan `testsigning`; matikan Secure Boot dulu
  (BIOS) bila perlu.
- Legal: driver + app hanya untuk mesin yang kamu miliki/authorize.
