#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

gdbus call --system --dest org.freedesktop.UPower --object-path /org/freedesktop/UPower/devices/DisplayDevice --method org.freedesktop.DBus.Properties.Get "org.freedesktop.UPower.Device" "Percentage"
