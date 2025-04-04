/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Farhan Khan <farhan@farhan.codes>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a template driver for FreeBSD's net80211 layer.
 * This is intended as a learning tool on the minimum implementation
 * of the net80211 layer entirely in software.
 *
 * This driver does not implement the USB, PCIe or SDIO layers, which would ordinarily
 * be responsible for the match, power on/off, state management, etc. Instead, this code
 * implements everything in software.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

// This file is generated during the build of the driver
#include "opt_global.h"

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/endian.h>
#include <sys/kdb.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <sys/types.h>
#include <sys/malloc.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include "i3e_driver.h"

// This function triggers whenever you run ifconfig wlan0 destroy
static void
i3e_vap_delete(struct ieee80211vap *vap)
{
	struct i3e_vap	*ivp = I3E_VAP(vap);
	ieee80211_vap_detach(vap);	// Minimum needed to delete the VAP
	free(ivp, M_80211_VAP);
}

/*
 * This function is run when the driver is unloaded.
 * In our case, this would be `kldunload i3e_driver`
 * Typically we want to:
 * - Disable any USB, PCIe or SDIO transfers.
 * - Free any active or pending Tx and Rx data.
 *   For context, Tx and Rx data are queue's abstracted for mbuf(9)
 * - XXX Drain sc_snd, trying to understand the difference between Tx/Rx.
 * - Destroy the sc->sc_mtx mutex
 */
static int
i3e_detach(struct i3e_softc *sc)
{
	I3E_LOCK(sc);
	sc->sc_detached = 1;
	I3E_UNLOCK(sc);

	ieee80211_ifdetach(&sc->sc_ic);
	mbufq_drain(&sc->sc_snd);
	mtx_destroy(&sc->sc_mtx);

	return (0);
}

static int
i3e_init(struct i3e_softc *sc)
{
	sc->sc_running = 1;
	return (0);
}

static void
i3e_stop(struct i3e_softc *sc)
{
	printf("i3e_stop\n");
}

/*
 * This is the handler for when a user runs ifconfig wlanX channel [CHAN NUMBER]
 * Your handler code communicates with the device to change the device channel
 * Very basic example handler: wi_set_channel
 * Helper function ieee80211_chan2ieee, converts channel to IEEE channel number
 */
static void
i3e_set_channel(struct ieee80211com *ic)
{
	struct i3e_softc *sc = ic->ic_softc;

	I3E_LOCK(sc);
	printf("i3e_set_channel to %d\n", ieee80211_chan2ieee(ic, ic->ic_curchan));
	I3E_UNLOCK(sc);
}

/*
 * Think of this as the main() function where previously queued mbufs are dequeued and
 * transmitted over the physical layer.
 *
 * The naming convention of DRIVER_start is confusing, but its what everyone does.
 * Simple example: zyd_start
 */
static void
i3e_start(struct i3e_softc *sc)
{
	return;
/*
	struct ieee80211_node *ni;
	struct mbuf *m;

	// LOCK?
	if (sc->sc->running == 0)
		return;

	// Loop through the Queued mbufs
	while(m = mbufq_dequeue(&sc->sc_snd) != NULL) {
		ni = (struct ieee80211_node *)m->m_pkthdr.rcvif;
		//if i3e_tx_start(sc, m, ni) != 0)
		m_freem(m);
		if_inc_counter(ni->ni_vap->iv_ifp, IFCOUNTER_OERRORS, 1);
		ieee80211_free_node(ni);
	}
*/
}

/*
 * This function receives an mbuf of a packet sent to the driver and adds it to
 * the sc_snd queue.
 * When a packet is sent to the device, this function will first queue it to sc_snd queue
 * (see description of sc_snd in the i3e_softc for details)
 *
 * i3e_start will then dequeue all mbufs and do the physical transmission.
 *
 * Simple example: ural_transmit
 */
static int
i3e_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct i3e_softc *sc = ic->ic_softc;
	int ret = 0;

	I3E_LOCK(sc);
	if (!sc->sc_running) {
		ret = ENXIO;
		goto fail;
	}

	ret = mbufq_enqueue(&sc->sc_snd, m);
	if (ret) {
		goto fail;
	}

	i3e_start(sc);
fail:
	I3E_UNLOCK(sc);
	return (ret);
}

/*
 * Raw Transmission is handled here
 * XXX Come back to this, needs more detail
*/
static int
i3e_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
	const struct ieee80211_bpf_params *params)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct i3e_softc *sc = ic->ic_softc;
	int ret = 0;

	/* this prevents management frames from being sent if we are not ready */
	I3E_LOCK(sc);
	if (!(sc->sc_running)) {
		ret = ENETDOWN;
		goto fail;
	}
	/* Raw transmission happens here */
fail:
//	printf("i3e_raw_xmit, return with %d\n", ret);
	I3E_UNLOCK(sc);
	return (ret);
}

// XXX Undocumented
/*
 * Multicast frames in 802.11 have a destination address of
 * FF:FF:FF:FF:FF:FF. This function is not necessary for all devices
 * but should at least be replaced to avoid a kernel messages
 * from `null_update_mcast`.
 */
static void
i3e_update_mcast(struct ieee80211com *ic)
{
}

/*
 * This function is triggered when the device is brought up or down
 * For example, `ifconfig wlan0 up` or `ifconfig wlan0 down`
 * The basic structure below is replicated in most drivers
 */
static void
i3e_parent(struct ieee80211com *ic)
{
	struct i3e_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	printf("i3e_parent\n");

	I3E_LOCK(sc);
	if (sc->sc_detached) { // If the device is already detached,
		I3E_UNLOCK(sc);
		return;
	}
	I3E_UNLOCK(sc);

	if (ic->ic_nrunning > 0) {
		if (i3e_init(sc) == 0)
			ieee80211_start_all(ic);
		else
			ieee80211_stop(vap);
	} else
		i3e_stop(sc);
}

//struct callout scancall;

static void print_hex(const void *buffer, size_t length) {
    const uint8_t *buf = (const uint8_t *)buffer;

    for (size_t i = 0; i < length; i += 16) {
        printf("00%04zX: ", i);  // Print offset starting with "00"
        for (size_t j = 0; j < 16 && (i + j) < length; j++) {
            printf("%02X ", buf[i + j]);  // Print each byte in hex
        }
        printf("\n");
    }   
}

#define IEEE80211_ADDR_LEN              6

#define IEEE80211_ELEMID_SSID           0
#define IEEE80211_ELEMID_RATES          1

#define IEEE80211_FC0_TYPE_MGT          0x00
#define IEEE80211_FC0_SUBTYPE_BEACON    0x80
#define IEEE80211_FC1_DIR_NODS          0x00    /* STA->STA */ 

#define IEEE80211_RATE_SIZE             8

#define SSID "NAFISA"
#define SSID_LEN 6

static void
custom_beacon(struct ieee80211com *ic)
{
//	struct ieee80211_frame *wh;
	struct mbuf *m = NULL;
//	uint8_t rawframe[100];
//	uint8_t *frm;
	int frame_len;

	uint8_t myframe[] =
"\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\x94\x98\x8F\x5A\x06\xE7"
"\x94\x98\x8F\x5A\x06\xE7\x40\x15\x85\x11\x21\x8C\x5E\x02\x00\x00"
"\x64\x00\x31\x14\x00\x0C\x54\x4D\x4F\x42\x49\x4C\x45\x2D\x30\x36"
"\x45\x31\x01\x08\x82\x84\x8B\x96\x0C\x12\x18\x24\x03\x01\x06\x05"
"\x04\x00\x01\x00\x00\x07\x06\x55\x53\x04\x01\x0B\x1E\x23\x02\x1D"
"\x00\x2A\x01\x00\x32\x04\x30\x48\x60\x6C\x30\x18\x01\x00\x00\x0F"
"\xAC\x04\x01\x00\x00\x0F\xAC\x04\x02\x00\x00\x0F\xAC\x02\x00\x0F"
"\xAC\x08\x8C\x00\x46\x05\x73\xDA\x00\x00\x0C\x2D\x1A\xEF\x19\x13"
"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x3D\x16\x06\x05\x06\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7F"
"\x0D\x04\x00\x0F\x02\x00\x00\x00\x40\x00\x40\x00\x00\x00\xBF\x0C"
"\x92\x79\x8B\x33\xAA\xFF\x00\x00\xAA\xFF\x00\x20\xC0\x05\x00\x08"
"\x00\xFC\xFF\xFF\x1D\x23\x0D\x01\x08\x1A\x40\x10\x02\x60\x48\x88"
"\x1F\x43\x81\x1C\x01\x08\x00\xAA\xFF\xAA\xFF\x1B\x1C\xC7\x71\x1C"
"\xC7\x71\xFF\x07\x24\xF4\x3F\x00\x28\xFC\xFF\xFF\x02\x27\x03\xFF"
"\x0E\x26\x0C\x03\xA4\xFF\x27\xA4\xFF\x42\x43\xFF\x62\x32\xFF\xDD"
"\x13\x8C\xFD\xF0\x01\x01\x02\x01\x00\x02\x01\x01\x03\x03\x01\x01"
"\x00\x04\x01\x01\xDD\x18\x00\x50\xF2\x02\x01\x01\x8C\x00\x03\xA4"
"\x00\x00\x27\xA4\x00\x00\x42\x43\x5E\x00\x62\x32\x2F\x00\xDD\x16"
"\x8C\xFD\xF0\x04\x00\x00\x49\x4C\x51\x03\x02\x09\x72\x01\x00\x00"
"\x00\x00\xFE\xFF\x00\x00\xDD\x07\x8C\xFD\xF0\x04\x01\x01\x00";

/*
	frm = rawframe;
	wh = (struct ieee80211_frame *)rawframe;

	// Build the packet here
	memset(wh, 0, sizeof(struct ieee80211_frame));
	wh->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;

	// Set destination, source, and BSSID to broadcast
	memset(wh->i_addr1, 0xff, IEEE80211_ADDR_LEN);  // Broadcast
	memset(wh->i_addr2, 0xaa, IEEE80211_ADDR_LEN);  // Fake source MAC
	memset(wh->i_addr3, 0xaa, IEEE80211_ADDR_LEN);  // Fake BSSID

        // Frame body starts after the header
        frm = (uint8_t *)(wh + 1);

        // SSID element
        *frm++ = IEEE80211_ELEMID_SSID;
        *frm++ = SSID_LEN;
        memcpy(frm, SSID, SSID_LEN);
        frm += SSID_LEN;

        // Rates
        *frm++ = IEEE80211_ELEMID_RATES;
        *frm++ = 0x8; // Size of 8
        memcpy(frm, "\x82\x84\x8b\x96\x24\x30\x48\x6c", 8);
        frm += 8;

        frame_len = frm - (uint8_t *)wh;
	frame_len = 42;
*/

	frame_len = 351;


	m = m_get2(frame_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		printf("Failed to m_get2.\n");
	}

	memcpy(mtod(m, uint8_t *), myframe, frame_len);
	
	// Copied from if_rum.c
	m->m_pkthdr.len = m->m_len = frame_len;

	print_hex(mtod(m, uint8_t *), frame_len);
	ieee80211_input_all(ic, m, 50, -95);
	printf("Custom beacon inserted!\n");
}

/*
 * As the name suggests, this function should set the card into scan-mode
 * which will seek out stations and listen to for endpoints
 */
static void
i3e_scan_start(struct ieee80211com *ic)
{
	struct i3e_softc *sc = ic->ic_softc;

	I3E_LOCK(sc);
	// Typically here we would send a command to the device to Start the device into scan-mode
	custom_beacon(ic);
	printf("%s: Scan Start\n", sc->sc_ic.ic_name);
	I3E_UNLOCK(sc);
}

/*
 * As the name suggests, this function should set the card out of scan-mode
 */
static void
i3e_scan_end(struct ieee80211com *ic)
{
	struct i3e_softc *sc = ic->ic_softc;

	I3E_LOCK(sc);
	// Typically here we would send a command to the device to stop the device into scan-mode
	printf("%s: Scan End\n", sc->sc_ic.ic_name);
	I3E_UNLOCK(sc);
}

/*
 * Updating the "state" ie mode of the interface
 * The device might need a hardware change depending on if its scanning, sleeping, etc
 * The typical pattern is to gracefully transition from the previous state, then
 * set the device to the new state.
 *
 * nstate is the new state
 * ostate is the current state in the vap
 *
 * The standard pattern is to run the default net80211 newstate
 * handler.
 *
 */
static int
i3e_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct i3e_vap *ivp = I3E_VAP(vap);
	struct ieee80211com *ic = vap->iv_ic;
	struct i3e_softc *sc = ic->ic_softc;
	enum ieee80211_state ostate;

	printf("%s: newstate\n", sc->sc_ic.ic_name);
	// I am not clear on the locking mechanism below, see here: https://lists.freebsd.org/archives/freebsd-wireless/2023-November/001627.html
	IEEE80211_UNLOCK(ic);
	I3E_LOCK(sc);

	// Here, we may choose to handle the previous state
	// The new state, potential values are listed in sys/net80211/ieee80211_proto.h
	ostate = vap->iv_state;

	switch(ostate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		break;
	case IEEE80211_S_AUTH:
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_CAC:
		break;
	case IEEE80211_S_RUN:
		break;
	case IEEE80211_S_CSA:
		break;
	case IEEE80211_S_SLEEP:
		break;
	default:
		break;
	}

	switch(nstate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		break;
	case IEEE80211_S_AUTH:
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_CAC:
		break;
	case IEEE80211_S_RUN:
		break;
	case IEEE80211_S_CSA:
		break;
	case IEEE80211_S_SLEEP:
		break;
	default:
		break;
	}

	I3E_UNLOCK(sc);
	IEEE80211_LOCK(ic);

	// Also execute the default newstate handler
	return (ivp->iv_newstate(vap, nstate, arg));
}

/*
 * This handler triggers when you create a VAP with
 * `ifconfig wlan create wlandev i3e0`
 * It will allocate the VAP, assign VAP handlers, and attach it.
 */
static struct ieee80211vap *
i3e_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
	enum ieee80211_opmode opmode, int flags,
	const uint8_t bssid[IEEE80211_ADDR_LEN],
	const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ieee80211vap *vap;
	struct i3e_vap *ivp;

	switch(opmode) {
	case IEEE80211_M_IBSS:
		printf("opmode = IEEE80211_M_IBSS, Adhoc mode\n");
		break;
	case IEEE80211_M_STA:
		printf("opmode = IEEE80211_M_IBSS, infrastructure station\n");
		break;
	case IEEE80211_M_WDS:
		printf("opmode = IEEE80211_M_WDS, WDS Link\n");
		break;
	case IEEE80211_M_AHDEMO:
		printf("opmode = IEEE80211_M_AHDEMO, Old lucent compatible adhoc demo\n");
		break;
	case IEEE80211_M_HOSTAP:
		printf("opmode = IEEE80211_M_HOSTAP, Software Access Point\n");
		break;
	case IEEE80211_M_MONITOR:
		printf("opmode = IEEE80211_M_MONITOR\n");
		break;
	case IEEE80211_M_MBSS:
		printf("opmode = IEEE80211_M_MBSS\n");
		break;
	default:
		printf("opmode = Unknown (%d)\n", opmode);
		break;
	}

	// Allocate the VAP
	ivp = malloc(sizeof(struct i3e_vap), M_80211_VAP, M_WAITOK | M_ZERO);
	vap = &ivp->vap;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode, flags, bssid) != 0) {
		printf("i3e_vap_setup failed\n");
		free(ivp, M_80211_VAP);
		return (NULL);
	}

	/*
	 * Common practice is to override the default method for changing
	 * the state and execute the default after a driver-specific handler
	 */
	ivp->iv_newstate = vap->iv_newstate;
	vap->iv_newstate = i3e_newstate;

	// Tell net80211 that a new VAP has been attached
	ieee80211_vap_attach(vap, ieee80211_media_change,
		ieee80211_media_status, mac);
	ic->ic_opmode = opmode;

	return (vap);
}

/*
 * Set the modes that the physical device is capable of.
 * The modes are enumerated in ieee80211_phymode (sys/net80211/_ieee80211.h)
 *
 * Simple example: zyd_getradiocaps
 */
static void
i3e_getradiocaps(struct ieee80211com *ic, int maxchans, int *nchans,
	struct ieee80211_channel chans[])
{
	uint8_t bands[IEEE80211_MODE_BYTES];
	memset(bands, 0, sizeof(bands));

	/*
	 * These are possible options that the device can physically module the
	 * signal and its associated frequency such as OFDM, CCK, GFSK, and 5GHz
	 * and 2GHz.
	 * The options are located in the enum ieee80211_phymode
	 * (sys/net80211/_ieee80211.h):
	 * - IEEE80211_MODE_AUTO
	 * - IEEE80211_MODE_11A
	 * - IEEE80211_MODE_11B
	 * - IEEE80211_MODE_11G
	 * - IEEE80211_MODE_FH
	 * - IEEE80211_MODE_TURBO_A
	 * - IEEE80211_MODE_TURBO_G
	 * - IEEE80211_MODE_11NA
	 * - IEEE80211_MODE_11NG
	 * - IEEE80211_MODE_HALF
	 * - IEEE80211_MODE_QUARTER
	 * - IEEE80211_MODE_VHT_2GHZ
	 * - IEEE80211_MODE_VHT_5GHZ
	 */

	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);
	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans, bands, 0);
}

static int i3e_wme_update(struct ieee80211com *ic)
{
	return (0);
}

static int i3e_attach(struct i3e_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	I3E_LOCK_INIT(sc);				// Initialize the Mutex lock

	mbufq_init(&sc->sc_snd, ifqmaxlen);

	ic->ic_softc = sc;
	ic->ic_name = "i3e0";					/* Ordinarily this would be device_get_nameunit(self), but manually setting it because
											 * this is not a real driver */
	ic->ic_phytype = IEEE80211_T_DS;		// Physical type, enum defined in sys/net/80211/_ieee80211.h

	ic->ic_caps =
	      IEEE80211_C_STA		/* station mode supported */
	    | IEEE80211_C_IBSS		/* IBSS mode supported */
	    | IEEE80211_C_MONITOR	/* monitor mode supported */
	    | IEEE80211_C_HOSTAP	/* HostAp mode supported */
	    | IEEE80211_C_AHDEMO	/* adhoc demo mode */
	    | IEEE80211_C_TXPMGT	/* tx power management */
	    | IEEE80211_C_SHPREAMBLE	/* short preamble supported */
	    | IEEE80211_C_SHSLOT	/* short slot time supported */
	    | IEEE80211_C_BGSCAN	/* bg scanning supported */
	    | IEEE80211_C_WPA		/* 802.11i */
	    | IEEE80211_C_WME		/* 802.11e */
	    | IEEE80211_C_PMGT		/* Station-side power mgmt */
	    ;

	ic->ic_cryptocaps =
	    IEEE80211_CRYPTO_WEP |
	    IEEE80211_CRYPTO_AES_CCM |
	    IEEE80211_CRYPTO_TKIPMIC |
	    IEEE80211_CRYPTO_TKIP;

	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */

	i3e_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans, ic->ic_channels);

	// Set the MAC address
	uint8_t macaddr[6] = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);

	ieee80211_ifattach(ic);
	// Counter-intuitively, these must be added afterwards because there are default ieee80211com handlers
	ic->ic_parent = i3e_parent;				// Defines what happens when a driver goes up/down
	ic->ic_scan_start =	i3e_scan_start;		// Puts the device into scan-mode
	ic->ic_scan_end = i3e_scan_end;			// Removes device from scan-mode
	ic->ic_vap_create = i3e_vap_create;		// Creates the VAP when you run `ifconfig wlan create wlandev i3e0`
	ic->ic_vap_delete = i3e_vap_delete;		// Opposite, deletes the VAP when you run `ifconfig wlan0 destroy`
	ic->ic_set_channel = i3e_set_channel;		// Change the channel
	ic->ic_raw_xmit = i3e_raw_xmit;
	ic->ic_transmit = i3e_transmit;			// Ordered packet transfer
	ic->ic_update_mcast = i3e_update_mcast;
	ic->ic_wme.wme_update = i3e_wme_update;

	ieee80211_announce(ic);

	return 0;
}

static int i3e_event_handler(struct module *module, int event_type, void *arg) {

  int ret = 0;						// function returns an integer error code, default 0 for OK

  switch (event_type) {				// event_type is an enum; let's switch on it
    case MOD_LOAD:					// if we're loading
  	  sc = malloc(sizeof(struct i3e_softc), M_80211_VAP, M_WAITOK | M_ZERO);
	  i3e_attach(sc);
      break;

    case MOD_UNLOAD:				// if were unloading
	  i3e_detach(sc);
	  // This free is handled by the FreeBSD's driver, but we have to manually simulate it here
	  free(sc, M_80211_VAP);
      break;

    default:
      ret = EOPNOTSUPP;
      break;
  }

  return(ret);					// return the appropriate value

}

static moduledata_t i3e_data = {
  "i3e",           // Name of our module
  i3e_event_handler,        // Name of our module's 'event handler' function
  NULL                      // Ignore for now :)
};

// Register the module with the kernel using:
//  the module name
//  our recently defined moduledata_t struct with module info
//  a module type (we're daying it's a driver this time)
//  a preference as to when to load the module
DECLARE_MODULE(freebsd_i3e, i3e_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
