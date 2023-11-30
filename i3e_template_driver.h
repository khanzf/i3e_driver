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
struct i3e_template_softc {
	struct ieee80211com		sc_ic;	// Used to store methods of how the base OS interacts with the driver andr how it interacts with VAP
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
};

static struct i3e_template_softc *sc;

struct i3e_template_vap {
	struct ieee80211vap		vap;
	int	(*iv_newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

#define I3E_TEMPLATE_VAP(vap)		((struct i3e_template_vap *)(vap))

//#define I3E_TEMPLATE_LOCK_INIT(_sc)	mtx_init(&(sc)->sc_mtx, device_get_nameunit((sc)->sc_dev), MTX_NETWORK_LOCK, MTX_DEF);
#define I3E_TEMPLATE_LOCK_INIT(_sc)	mtx_init(&(sc)->sc_mtx, "i3e0", MTX_NETWORK_LOCK, MTX_DEF);
#define I3E_TEMPLATE_LOCK(_sc)		mtx_lock(&(_sc)->sc_mtx)
#define I3E_TEMPLATE_UNLOCK(_sc)	mtx_unlock(&(_sc)->sc_mtx)

#define I3E_TEMPLATE_VAP(vap)		((struct i3e_template_vap *)(vap))
