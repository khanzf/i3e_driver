
# FreeBSD net80211 template driver

## Introduction

This is a templated implementation of FreeBSD's 15-CURRENT net80211 layer. This driver is intended as a learning resource.

This driver is as much a project for myself as it is for any future readers :)

The driver does not implement PCIe, USB or SDIO layers. Rather, everything is implemented in software.

## How to Test code

On a FreeBSD host, run the following:

```
git clone https://github.com/khanzf/i3e_template_driver
cd i3e_template_driver
make
make load
```
This should create a `i3e0` interface. You can now use this to create a VAP.

To create a `wlan0` VAP, run the following command:
```
ifconfig wlan create wlandev i3e0
```

## How to read

Like all drivers, this might come off like a wall of code with no context.
The order to read this code is:
1) `i3e_attach` - Executed after the device is identified by
the `probe` function. Note, because this driver is a software-only
implementation, not a real USB, PCI or SDIO driver. It should power on the device, read any hardcoded values (ie, device version, MAC address, etc) and enable the device accordingly. The end result will be the `i3e0` interface.
    * Subfunction `i3e_getradiocaps` - Sets the device modes and frequencies. Technically this could be merged or inlined into `i3e_attach`, but keeping it a separate function is convention.
2) `i3e_parent`, `i3e_vap_create` and `i3e_init` - These three functions operate in tandem when creating the interface with `ifconfig wlan create wlandev i3e`.
    * `i3e_vap_create` - This is executed when `wlan`, which is a virtual interface to connect to multiple nodes at once.
    * `i3e_parent` - This function is executed when the device is set to `up` or `down`. It must be assigned in `i3e_attach`, such as `ic->ic_parent = i3e_parent`. If the device is off, it will run `i3e_init` and then start or stop all VAPs.
    * `i3e_init` - This function turns the device on and starts reading or writing.

### Explanation

## Source Files

## ieee80211com

## ieee80211vap

## LICENSE

This code is licensed under the 2-Clause BSD.

## Author

The author of this is code Farhan Khan (farhan@farhan.codes)
