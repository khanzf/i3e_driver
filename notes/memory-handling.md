# Memory Handling

This is a high-level explanation of how WiFi drivers manage and pass frames to the net80211 subsystem on FreeBSD. In short, the WiFi driver:
1) Preceives raw USB frames
2) Processes them as needed
3) Copy the 802.11 frame to an `mbuf`
4) Submit the `mbuf` to the net80211 subsystem

## Attachment Pre-Allocation

USB drivers utilize pre-allocated data objects to transfer data to and from the device. These objects are allocated during the attachment phase and used during transfering and receiving.

The typical structure is as follows:

```
struct DRIVER_data {
	struct DRIVER_softc		*sc; // Reference to the softc
	uint8_t			*buf; // Will get malloc() run on it
	uint16_t			buflen;
	struct mbuf		       *m;
	struct ieee80211_node	*ni;
	STAILQ_ENTRY(DRIVER_data) next;
};
```

1) The `DRIVER_softc` value is a backpointer to the `softc` instance of the device.
2) The `buf` value is malloc()'d to the largest possible size of a frame from the device.
3) `buflen` specifies the actual size of the data at any given moment.
4) `m` is a pointer to the `mbuf` associated with the raw USB transfer.
5) `ni` is a pointer to the structure holding information about the node on the network.
6) `next` is a queue structure to the next buffer.

A set of objects are typically placed in a queue. By default, all objects are placed in an inactive queue and moved into the active queue during operation.

## Active versus Inactive

As mentioned, drivers maintain two sets of data queues: active and inactive. At attachment, all objects are considered inactive. When a new frame is sent to the device, the driver will run `DRIVER_LOCK` to prevent concurrent changes to softc`, then grab the first available member of the inactive queue. The data buffer is then placed in the active list so that it is not concurrently used by another frame. When complete, the data object is placed back into the inactive list.

Note, if the device receives more frames than total number of data objects, the standard behavior is to drop the frame. Therefore, ensure that your driver has a sufficient number of data objects without unnecessarily wasting system memory.

## Rx Operation

During USB operation, the USB stack will trigger an interrupt (irq) or data (bulk) transfer.

As mentioned above, the device will dequeue the first inactive data object. The pre-allocated buffer in the object is used to store the raw data from the device, which typically consists of device-specific header and 802.11 frame. Using a pre-allocated buffer here prevents needing to call malloc(), a performance-expensive call, during device operation. After transfer, the device can run `DRIVER_UNLOCK` as the lock is no longer needed and the unlock allows other threads to continue.

From here, the driver will process the frame as needed. This typically means extracting RSSI, signal strength data and identifying the length of the 802.11 frame. The driver will request an `mbuf` to match the size of the frame and copy the data to the `mbuf`. Note, requesting an `mbuf` does not result in calling `malloc`, as the mbufs are pre-allocated by the kernel's UMA memory subsystem.

Finally, the `mbuf`, containing only the 802.11 frame, is submitted to the driver via `ieee80211_input` or a related function.

Drivers do not need to manually free the `mbuf`, as this is handled by net80211.
