# Device Locking

FreeBSD wifi drivers typically place a driver-level lock around the driver handler functions, especially if they change the state of the device.

For example, a typical `newstate` handler will function as:

```
vap->iv_newstate = otus_newstate;

int
otus_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
...snippet...
	IEEE80211_UNLOCK(ic);
	OTUS_LOCK(sc);

	switch(nstate) {
...snippet...
	}

...snippet...

	OTUS_UNLOCK(sc);
	IEEE80211_LOCK(ic);
	return (uvp->newstate(vap, nstate, arg));
}

```

The result is that any child functions operate on the assumption that that the driver mutex is locked. This is significant for USB, which requires its mutex to be locked prior to calling `usbd_transfer_start`.

Note for porters: This is very different from OpenBSD, which does not follow this idiom.

