#!/usr/sbin/dtrace -s

#pragma D option quiet

fbt:kernel:ieee80211_parse_beacon:entry
{
	this->node = (struct ieee80211_node *)arg0;
	this->vap = (struct ieee80211vap *)this->node->ni_vap;
	this->scan = (struct ieee80211_scanparams *)arg3;

	printf("Entry of ieee80211_parse_beacon\n");
	printf("==============================\n");
	printf("arg0: ieee80211_node *ni:         0x%p\n", arg0); 
	printf("arg1: struct mbuf *m0:            0x%p\n", arg1); 
	printf("arg2: eee80211_channel:           0x%x\n", arg2); 
	printf("arg3: ieee80211_scanparams *scan: 0x%02x\n", arg3);
	printf("-------------------------------\n");
	printf("Interface name: %s\n", stringof(this->vap->iv_ifp->if_xname));

	printf("VAP state: %d\n", this->vap->iv_state);
	printf("VAP flags: 0x%x\n", this->vap->iv_flags);
	printf("vap->iv_stats.is_rx_beacon: %d\n", this->vap->iv_stats.is_rx_beacon);
	printf("scan->chan:  %d\n", this->scan->chan);
	printf("scan->bchan: %d\n", this->scan->bchan);
	printf("vap->iv_stats.is_rx_mgtdiscard: %d\n", this->vap->iv_stats.is_rx_mgtdiscard);
	printf("vap->iv_stats.is_rx_chanmismatch: %d\n", this->vap->iv_stats.is_rx_chanmismatch);
}

fbt:kernel:ieee80211_parse_beacon:return
{
	printf("Return of ieee80211_parse_beacon\n");
	printf("==============================\n");
	printf("Return: int = 0x%02x\n", arg1);
	printf("-------------------------------\n");
	printf("scan->chan:  %d\n", this->scan->chan);
	printf("scan->bchan: %d\n", this->scan->bchan);
	printf("\n");
}
