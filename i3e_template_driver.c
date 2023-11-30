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

#include "i3e_template_driver.h"

// This function triggers whenever you run ifconfig wlan0 destroy
static void
i3e_template_vap_delete(struct ieee80211vap *vap)
{
	struct i3e_template_vap	*ivp = I3E_TEMPLATE_VAP(vap);
	ieee80211_vap_detach(vap);			// Minimum needed to delete the VAP
	free(ivp, M_80211_VAP);
}

static int
i3e_template_detach(struct i3e_template_softc *sc)
{
	I3E_TEMPLATE_LOCK(sc);
	sc->sc_detached = 1;
	I3E_TEMPLATE_UNLOCK(sc);

	ieee80211_ifdetach(&sc->sc_ic);
	mbufq_drain(&sc->sc_snd);
	mtx_destroy(&sc->sc_mtx);

	return (0);
}

static int
i3e_template_init(struct i3e_template_softc *sc)
{
	printf("i3e_template_init\n");
	sc->sc_running = 1;
	return (0);
}

static void
i3e_template_stop(struct i3e_template_softc *sc)
{
	printf("i3e_template_stop\n");
}

/*
 * This is the handler for when a user runs ifconfig wlanX channel [CHAN NUMBER]
 * Your handler code communicates with the device to change the device channel
 * Very basic example handler: wi_set_channel
 * Helper function ieee80211_chan2ieee, converts channel to IEEE channel number
 */
static void
i3e_template_set_channel(struct ieee80211com *ic)
{
	struct i3e_template_softc *sc = ic->ic_softc;

	I3E_TEMPLATE_LOCK(sc);
	printf("i3e_template_set_channel to %d\n", ieee80211_chan2ieee(ic, ic->ic_curchan));
	I3E_TEMPLATE_UNLOCK(sc);
}

/*
 * Example driver: ural_transmit
 */
static int
i3e_template_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct i3e_template_softc *sc = ic->ic_softc;
	int ret = 0;

	I3E_TEMPLATE_LOCK(sc);
	if (!sc->sc_running) {
		ret = ENXIO;
		goto fail;
	}

	ret = mbufq_enqueue(&sc->sc_snd, m);
	if (ret) {
		goto fail;
	}

//	i3e_template_start(sc);
fail:
	I3E_TEMPLATE_UNLOCK(sc);
	return (ret);
}

/*
 * Raw Transmission is handled here
 * XXX Come back to this, needs more detail
*/
static int
i3e_template_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
	const struct ieee80211_bpf_params *params)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct i3e_template_softc *sc = ic->ic_softc;
	int ret = 0;


	/* this prevents management frames from being sent if we are not ready */
	I3E_TEMPLATE_LOCK(sc);
	if (!(sc->sc_running)) {
		ret = ENETDOWN;
		goto fail;
	}
	/* Raw transmission happens here */
fail:
//	printf("i3e_template_raw_xmit, return with %d\n", ret);
	I3E_TEMPLATE_UNLOCK(sc);
	return (ret);
}

static void
i3e_template_update_mcast(struct ieee80211com *ic)
{
	printf("i3e_template_updadte_mcast unimplemented.\n");
}

/*
 * This function is triggered when the device is brought up or down
 * For example, `ifconfig wlan0 up` or `ifconfig wlan0 down`
 * The basic structure below is replicated in most drivers
 */
static void
i3e_template_parent(struct ieee80211com *ic)
{
	struct i3e_template_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);
	printf("i3e_template_parent\n");

	I3E_TEMPLATE_LOCK(sc);
	if (sc->sc_detached) { // If the device is already detached,
		I3E_TEMPLATE_UNLOCK(sc);
		return;
	}
	I3E_TEMPLATE_UNLOCK(sc);

	if (ic->ic_nrunning > 0) {
		if (i3e_template_init(sc) == 0)
			ieee80211_start_all(ic);
		else
			ieee80211_stop(vap);
	} else
		i3e_template_stop(sc);
}

static void
i3e_template_scan_start(struct ieee80211com *ic)
{
	struct i3e_template_softc *sc = ic->ic_softc;

	I3E_TEMPLATE_LOCK(sc);
	// Typically here we would send a command to the device to Start the device into scan-mode
	printf("%s: Scan Start\n", sc->sc_ic.ic_name);
	I3E_TEMPLATE_UNLOCK(sc);
}

static void
i3e_template_scan_end(struct ieee80211com *ic)
{
	struct i3e_template_softc *sc = ic->ic_softc;

	I3E_TEMPLATE_LOCK(sc);
	// Typically here we would send a command to the device to stop the device into scan-mode
	printf("%s: Scan End\n", sc->sc_ic.ic_name);
	I3E_TEMPLATE_UNLOCK(sc);
}

static int
i3e_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct i3e_template_vap *ivp = I3E_TEMPLATE_VAP(vap);
	struct ieee80211com *ic = vap->iv_ic;
	struct i3e_template_softc *sc = ic->ic_softc;
	enum ieee80211_state ostate;

	printf("%s: newstate\n", sc->sc_ic.ic_name);
	// XXX Figure out why the IEEE80211_UNLOCK
	IEEE80211_UNLOCK(ic);
	I3E_TEMPLATE_LOCK(sc);

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

	I3E_TEMPLATE_UNLOCK(sc);
	IEEE80211_LOCK(ic);

	// Also execute the default newstate handler
	return (ivp->iv_newstate(vap, nstate, arg));
}

static struct ieee80211vap *
i3e_template_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
	enum ieee80211_opmode opmode, int flags,
	const uint8_t bssid[IEEE80211_ADDR_LEN],
	const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ieee80211vap *vap;
	struct i3e_template_vap *ivp;

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
		printf("opmdoe = IEEE80211_M_MONITOR\n");
		break;
	case IEEE80211_M_MBSS:
		printf("opmode = IEEE80211_M_MBSS\n");
		break;
	default:
		printf("opmode = Unknown (%d)\n", opmode);
		break;
	}

	ivp = malloc(sizeof(struct i3e_template_vap), M_80211_VAP, M_WAITOK | M_ZERO);
	vap = &ivp->vap;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode, flags, bssid) != 0) {
		uprintf("i3e_vap_setup failed\n");
		free(ivp, M_80211_VAP);
		return (NULL);
	}

	/* Common practice is to override the default method for changing the state */
	ivp->iv_newstate = vap->iv_newstate;
	vap->iv_newstate = i3e_newstate;

	ieee80211_vap_attach(vap, ieee80211_media_change,
		ieee80211_media_status, mac);
	ic->ic_opmode = opmode;

	return (vap);
}

static int i3e_template_attach(struct i3e_template_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic; 

	I3E_TEMPLATE_LOCK_INIT(sc);				// Initialize the Mutex lock

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

	//ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
//rum_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
//559        ic->ic_channels);


	uint8_t bands[IEEE80211_MODE_BYTES];
	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11B);
//	setbit(bands, IEEE80211_MODE_11G);
	ieee80211_add_channels_default_2ghz(ic->ic_channels, IEEE80211_CHAN_MAX, &ic->ic_nchans, bands, 0);

	// Set the MAC address
	uint8_t macaddr[6] = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);

	ieee80211_ifattach(ic);
	// Counter-intuitively, these must be added afterwards because there are default ieee80211com handlers
	ic->ic_parent = i3e_template_parent;	// Defines what happens when a driver goes up/down
	ic->ic_scan_start =	i3e_template_scan_start;	// Puts the device into scan-mode
	ic->ic_scan_end = i3e_template_scan_end;		// Removes device from scan-mode
	ic->ic_vap_create = i3e_template_vap_create;
	ic->ic_vap_delete = i3e_template_vap_delete;
	ic->ic_set_channel = i3e_template_set_channel;
	ic->ic_raw_xmit = i3e_template_raw_xmit;
	ic->ic_transmit = i3e_template_transmit;
	ic->ic_update_mcast = i3e_template_update_mcast;

	ieee80211_announce(ic);

	return 0;
}

static int i3e_event_handler(struct module *module, int event_type, void *arg) {

  int retval = 0;					// function returns an integer error code, default 0 for OK

  switch (event_type) {				// event_type is an enum; let's switch on it
    case MOD_LOAD:					// if we're loading
  	  sc = malloc(sizeof(struct i3e_template_softc), M_80211_VAP, M_WAITOK | M_ZERO);
	  i3e_template_attach(sc);
      break;

    case MOD_UNLOAD:				// if were unloading
	  i3e_template_detach(sc);
      break;

    default:						// if we're doing anything else
      retval = EOPNOTSUPP;			// return a 'not supported' error
      break;
  }

  return(retval);					// return the appropriate value

}

static moduledata_t i3e_data = {
  "i3e_template",           // Name of our module
  i3e_event_handler,        // Name of our module's 'event handler' function
  NULL                      // Ignore for now :)
};

// Register the module with the kernel using:
//  the module name
//  our recently defined moduledata_t struct with module info
//  a module type (we're daying it's a driver this time)
//  a preference as to when to load the module
DECLARE_MODULE(freebsd_i3e, i3e_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
