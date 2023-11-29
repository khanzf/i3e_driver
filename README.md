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

### Explanation

## Source Files

## ieee80211com

## ieee80211vap

## LICENSE

This code is licensed under the 2-Clause BSD.

## Author

The author of this is code Farhan Khan (farhan@farhan.codes)
