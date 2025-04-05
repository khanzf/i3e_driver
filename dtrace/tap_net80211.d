#!/usr/sbin/dtrace -s

/*
 * Run with sudo ./net80211_tap.d
 */

inline int IEEE80211_ADDR_LEN = 6;

struct ieee80211_frame {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
} __packed;

struct ieee80211_channel {
	uint32_t	ic_flags;	/* see below */
	uint16_t	ic_freq;	/* primary centre frequency in MHz */
	uint8_t		ic_ieee;	/* IEEE channel number */
	int8_t		ic_maxregpower;	/* maximum regulatory tx power in dBm */
	int8_t		ic_maxpower;	/* maximum tx power in .5 dBm */
	int8_t		ic_minpower;	/* minimum tx power in .5 dBm */
	uint8_t		ic_state;	/* dynamic state */
	uint8_t		ic_extieee;	/* HT40 extension channel number */
	int8_t		ic_maxantgain;	/* maximum antenna gain in .5 dBm */
	uint8_t		ic_pad;
	uint16_t	ic_devdata;	/* opaque device/driver data */
	uint8_t		ic_vht_ch_freq1; /* VHT primary freq1 IEEE value */
	uint8_t		ic_vht_ch_freq2; /* VHT secondary 80MHz freq2 IEEE value */
	uint16_t	ic_freq2;	/* VHT secondary 80MHz freq2 MHz */
};

/*
fbt::ieee80211_process_mimo:return {
}

fbt::ieee80211_input_all:entry {
}
*/

/*
fbt:kernel:sta_recv_mgmt:entry {
	self->ni	= arg0;
	self->m0	= arg1;
	self->subtype	= arg2;
	self->rxs	= arg3;
	self->rssi	= arg4;
	self->nf	= arg5;

	self->vap	= arg0->ni;

	printf("vap %d\n", arg0->ni_vap);
}
*/

fbt::sta_recv_mgmt:entry
{
    /* arg0 is the first argument, a pointer to ieee80211_node */
    this->node = (struct ieee80211_node *)arg0;

    /* Print some fields of the ieee80211_node structure */
    printf("Node address: %s\n", stringof(this->node->ni_macaddr));
    printf("RSSI: %d\n", this->node->ni_rssi);
    printf("State: %d\n", this->node->ni_state);
}

fbt:kernel:sta_recv_mgmt:return {
}
