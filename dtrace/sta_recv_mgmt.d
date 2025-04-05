#!/usr/sbin/dtrace -s

#pragma D option quiet

fbt::sta_recv_mgmt:entry
{
	this->node = (struct ieee80211_node *)arg0;
	this->vap = (struct ieee80211vap *)this->node->ni_vap;

 	this->is_beacon_bad = this->vap->iv_stats.is_beacon_bad;

	printf("Entry of sta_recv_mgmt\n");
	printf("==============================\n");
	printf("arg0: ieee80211_node *ni:      0x%p\n", arg0); 
	printf("arg1: struct mbuf *m0:         0x%p\n", arg1); 
	printf("arg2: int subtype:             0x%x\n", arg2); 
	printf("arg3: ieee80211_rx_stats *rxs: 0x%02x\n", arg3);
	printf("arg4: int rssi:                %d\n", arg4);
	printf("arg5: int nf:                  %d\n", arg5);
	printf("-------------------------------\n");
	printf("Interface name: %s\n", stringof(this->vap->iv_ifp->if_xname));

	printf("VAP state: %d\n", this->vap->iv_state);
	printf("VAP flags: 0x%x\n", this->vap->iv_flags);
	printf("vap->iv_stats.is_rx_beacon: %d\n", this->vap->iv_stats.is_rx_beacon);
	printf("vap->iv_stats.is_rx_mgtdiscard: %d\n", this->vap->iv_stats.is_rx_mgtdiscard);
}

fbt::sta_recv_mgmt:return
{
	printf("Return of sta_recv_mgmt");
	printf("==============================\n");
}
