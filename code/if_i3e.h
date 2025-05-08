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
#include <sys/conf.h>
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

/*
 * BSD drivers store driver instance-specific variables in their "softc"
 * structure.
 */
struct i3e_softc {
	struct ieee80211com		sc_ic;	// This must be the first element, used to store methods of how the base OS interacts with the driver andr how it interacts with VAP
	struct mtx				sc_mtx; // Device-wide locking mutex 

	int						sc_detached;
	int						sc_running;

	/*
	 * mbufq and its associated functions are not clearly defined anywhere. It is an implementation of
	 * `struct mbuf`. It is a method of queueing frames to be sent in memory prior to sending it.
	 * The purpose of this is performance, specifically when software operates faster than the hardware
	 * can push hardware in the data out.
	 * Its associated functions are located in sys/sys/mbuf.h.
	 */
	struct mbufq			sc_snd;

	struct cdev				*dev;
};

static struct i3e_softc *sc;

// This structure overrides ieee80211vap, so an instance of it must come first.
struct i3e_vap {
	struct ieee80211vap		vap;
	int	(*iv_newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

#define I3E_VAP(vap)		((struct i3e_vap *)(vap))

struct i3e_node {
	struct ieee80211_node	ni; // This must be the first element
	/* You can put anything necessary here */
};

#define I3E_LOCK_INIT(_sc)	mtx_init(&(sc)->sc_mtx, "i3e0", MTX_NETWORK_LOCK, MTX_DEF);
#define I3E_LOCK(_sc)		mtx_lock(&(_sc)->sc_mtx)
#define I3E_UNLOCK(_sc)	mtx_unlock(&(_sc)->sc_mtx)

#define I3E_VAP(vap)		((struct i3e_vap *)(vap))

static void i3e_vap_delete(struct ieee80211vap *vap);
static int i3e_detach(struct i3e_softc *sc);
static int i3e_init(struct i3e_softc *sc);
static void i3e_stop(struct i3e_softc *sc);
static void i3e_set_channel(struct ieee80211com *ic);
static void i3e_start(struct i3e_softc *sc);
static int i3e_transmit(struct ieee80211com *ic, struct mbuf *m);
static int i3e_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params);
static void i3e_update_mcast(struct ieee80211com *ic);
static void i3e_parent(struct ieee80211com *ic);
static void i3e_scan_start(struct ieee80211com *ic);
static void i3e_scan_end(struct ieee80211com *ic);
static int i3e_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate,
    int arg);
static struct ieee80211vap *i3e_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags, const uint8_t bssid[IEEE80211_ADDR_LEN],
	const uint8_t mac[IEEE80211_ADDR_LEN]);
static void i3e_getradiocaps(struct ieee80211com *ic, int maxchans, int *nchans,
    struct ieee80211_channel chans[]);
static int i3e_wme_update(struct ieee80211com *ic);
static struct ieee80211_node *i3e_node_alloc(struct ieee80211vap *vap,
    const uint8_t mac[IEEE80211_ADDR_LEN]);
static int i3e_attach(struct i3e_softc *sc);
static int i3e_event_handler(struct module *module, int event_type, void *arg);
static int i3e_write(struct cdev *dev, struct uio *uio, int ioflag);
