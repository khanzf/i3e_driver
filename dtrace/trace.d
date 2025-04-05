#!/usr/sbin/dtrace -s

/* Run with -F flag: sudo ./trace.d -F */

fbt::ieee80211_*:entry,fbt::ieee80211_*:return {}
