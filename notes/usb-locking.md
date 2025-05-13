# USB Locking

The `newstate` handler does two locks upon start:

```
IEEE80211_UNLOCK(ic);
DRIVER_LOCK(sc);
```

This is significant for USB, which requires its mutex to be locked prior to calling `usbd_transfer_start`.
In the event that code is shared between the `attach` handler and regular operations, the best approach is to place the lock *before* the entry into shared code.
