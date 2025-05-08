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

#include "if_i3e.h"

/*
 * Forward declaring structure, which holds the read/write/ioctl
 * handlers This variable is defined at the end of this file.
 * Forward declaration would not be necessary if I put all
 * function prototypes above.
 */
static struct cdevsw i3e_cdevsw;

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

	if (sc->dev)
		destroy_dev(sc->dev);

	mbufq_drain(&sc->sc_snd);
	mtx_destroy(&sc->sc_mtx);
	ieee80211_ifdetach(&sc->sc_ic);

	return (0);
}

/*
 * The *_init function power on the device and do whatever
 * initial configurations are necessary to atomize Tx and Rx.
 * This function is often called by *_parent when the device
 * is labeled as not running.
 * Other drivers capture this as a flag, either works.
 */
static int
i3e_init(struct i3e_softc *sc)
{
	/* This labels the device as running */
	sc->sc_running = 1;
	return (0);
}

/*
 * Power off the device, drain all queued mbufs
 */
static void
i3e_stop(struct i3e_softc *sc)
{
	sc->sc_running = 0;
	printf("i3e_stop\n");
}

/*
 * This is the handler for when the channel is
 * changed, such as during a scan or manually
 * when a user runs:
 *  ifconfig wlanX channel [CHAN NUMBER]
 * Your handler code communicates with the device to change the device channel
 * Very basic example handler: wi_set_channel
 * Helper function ieee80211_chan2ieee, converts channel to IEEE channel number
 */
static void
i3e_set_channel(struct ieee80211com *ic)
{
	struct i3e_softc *sc = ic->ic_softc;

	I3E_LOCK(sc);
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

	/* this prevents rames from being sent if we are not ready */
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
 * The basic structure below is replicated in most drivers. If the
 * device is not running, as determined by the number of vaps,
 * then the common idiom is to call the *_init function.
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

static void
custom_beacon(struct ieee80211com *ic)
{
	struct mbuf *m = NULL;
	int frame_len;

	uint8_t myframe[] =
		"\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\x11\x22\x33\x44\x55"
		"\x00\x11\x22\x33\x44\x55\x10\x27\x8A\xD1\x3C\x19\x02\x00\x00\x00"
		"\x64\x00\x11\x14\x00\x06"
		"\x4e\x41\x46\x49\x53\x41"
		"\x01\x08"
		"\x82\x84\x8B\x96\x24\x30\x48\x6C\x03\x01\x0B\x05\x04\x00\x01\x00"
		"\x00\x2A\x01\x04\x32\x04\x0C\x12\x18\x60\x30\x14\x01\x00\x00\x0F"
		"\xAC\x04\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x02\x0C\x00"
		"\x0B\x05\x0E\x00\x32\x00\x00\x46\x05\x72\x08\x01\x00\x00\x2D\x1A"
		"\xBD\x09\x1B\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3D\x16\x0B\x08\x04\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x7F\x08\x04\x00\x08\x00\x00\x00\x00\x40\xDD\x18\x00\x50"
		"\xF2\x04\x10\x4A\x00\x01\x10\x10\x44\x00\x01\x02\x10\x49\x00\x06"
		"\x00\x37\x2A\x00\x01\x20\xDD\x09\x00\x10\x18\x02\x0E\x00\x1C\x00"
		"\x00\xDD\x18\x00\x50\xF2\x02\x01\x01\x80\x00\x03\xA4\x00\x00\x27"
		"\xA4\x00\x00\x42\x43\x5E\x00\x62\x32\x2F\x00";

	frame_len = 233;


	m = m_get2(frame_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		printf("Failed to m_get2.\n");
	}

	memcpy(mtod(m, uint8_t *), myframe, frame_len);
	
	// Copied from if_rum.c
	m->m_pkthdr.len = m->m_len = frame_len;

	ieee80211_input_all(ic, m, 50, -95);
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

	/*
	 * I am not clear on the locking mechanism below, See here:
	 * https://lists.freebsd.org/archives/freebsd-wireless/2023-November/001627.html
	 */
	IEEE80211_UNLOCK(ic);
	I3E_LOCK(sc);

	/*
	 * Here, we may choose to handle the previous state
	 * The new state, potential values are listed in
	 * sys/net80211/ieee80211_proto.h
	 */
	ostate = vap->iv_state;

	switch(ostate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		/* Happens when scanning */
		break;
	case IEEE80211_S_AUTH:
		/* When the device is authenticating to a station */
		break;
	case IEEE80211_S_ASSOC:
		/* Post Authentication, Associating */
		break;
	case IEEE80211_S_CAC:
		/* Channel Availability Check */
		break;
	case IEEE80211_S_RUN:
		/* Regular usage, post association */
		break;
	case IEEE80211_S_CSA:
		/* Channel Switch Announce pending */
		break;
	case IEEE80211_S_SLEEP:
		/* Power Save Mode */
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

	/* Wifi modes are listed in sys/net80211/_ieee80211.h */
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

static int
i3e_wme_update(struct ieee80211com *ic)
{
	return (0);
}

/*
 * The ieee80211_node stores information about other devices (nodes) that the device
 * is aware of.
 * As with other structures, net80211 allows you to extend the node for
 * device-specific considerations if necessary. This function simply allocates the memory
 * and initializes it as needed
 */
static struct ieee80211_node *
i3e_node_alloc(struct ieee80211vap *vap, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct i3e_node *in;

	in = malloc(sizeof(struct i3e_node), M_80211_NODE, M_NOWAIT | M_ZERO);
	if (in == NULL) {
		printf("i3e: Unable to allocat/e node\n");
	}
	return (struct ieee80211_node *)in;
}

static int
i3e_attach(struct i3e_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	I3E_LOCK_INIT(sc);				// Initialize the Mutex lock

	mbufq_init(&sc->sc_snd, ifqmaxlen);

	ic->ic_softc = sc;
	ic->ic_name = "i3e0";					/* Ordinarily this would be device_get_nameunit(self), but manually setting it because
											 * this is not a real driver */
	ic->ic_phytype = IEEE80211_T_FH;		// Physical type, enum defined in sys/net/80211/_ieee80211.h

	ic->ic_caps =
	    IEEE80211_C_STA |		/* station mode supported */
	    IEEE80211_C_IBSS |		/* IBSS mode supported */
	    IEEE80211_C_MONITOR |	/* monitor mode supported */
	    IEEE80211_C_HOSTAP |	/* HostAp mode supported */
	    IEEE80211_C_AHDEMO |	/* adhoc demo mode */
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT |	/* short slot time supported */
	    IEEE80211_C_BGSCAN |	/* bg scanning supported */
	    IEEE80211_C_WPA |		/* 802.11i */
	    IEEE80211_C_WME |		/* 802.11e */
	    IEEE80211_C_PMGT;	/* Station-side power mgmt */

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
	ic->ic_transmit = i3e_transmit;			// Buffered frame queueing transfer
	ic->ic_node_alloc = i3e_node_alloc;		// Allocates node information specific to device. Not all devices need this, but may be necessary
	ic->ic_update_mcast = i3e_update_mcast;
	ic->ic_wme.wme_update = i3e_wme_update;

	sc->dev = make_dev(&i3e_cdevsw, 0, UID_ROOT,
		GID_OPERATOR, 0600, "i3e%d", 0);
	sc->dev->si_drv1 = sc;

	// This announces the interface in the kernel messages
	ieee80211_announce(ic);

	return 0;
}

static int
i3e_event_handler(struct module *module, int event_type, void *arg)
{
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

static int
i3e_write(struct cdev *dev, struct uio *uio, int ioflag)
{
//	uint8_t *frame;
	int error = 0;

/*
	frame = malloc(uio->uio_resid + 1, M_DEVBUF, M_WAITOK);
	error = uiomove(frame, uio->uio_resid, uio);

	if (error)
		goto error;

	printf("Got the data: %s\n", s);
*/
//error:
//	free(frame, M_BUFDEV);
	return (error);
}

static struct cdevsw i3e_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	0,
	.d_write =	i3e_write,
	.d_name =	"i3e",
};

static moduledata_t i3e_data = {
	"i3e",			// Name of our module
	i3e_event_handler,	// Name of our module's 'event handler' function
	NULL			// Not yet sure what this does
};

/*
 * Register the module with the kernel using:
 * 1) The module name
 * 2) Our recently defined moduledata_t struct with module info
 * 3) A module type (we're daying it's a driver this time)
 * 4) A preference as to when to load the module
 */
DECLARE_MODULE(freebsd_i3e, i3e_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
