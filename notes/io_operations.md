# IO Operations in if_i3e

Drivers typically do not have IO descriptor handlers, such as read, write, ioctl, etc.
These were placed in the driver to simulate traffic "from the air" arriving to driver.

## Write Operation

Upon creation of a VAP, you will see `/dev/i3e0_vap0`. Any data written to the device will function
as a raw frame that is submitted to net80211 via `ieee80211_input_all`.
