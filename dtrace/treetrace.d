#!/usr/sbin/dtrace -s

/*
 * Used to see net80211 handoff and driver execution tree
 * Run with -F flag: sudo ./trace.d -F
 */

fbt::ieee80211_*:,fbt:if_i3e:: {}
