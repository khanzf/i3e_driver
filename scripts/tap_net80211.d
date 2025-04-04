#!/usr/sbin/dtrace -s

/*
 * Run with sudo ./net80211_tap.d
 */

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

struct ieee80211_channel *c;

fbt::ieee80211_process_mimo:return {
}

fbt::ieee80211_input_all:entry {
}

fbt::ieee80211_input_all:return {
}
