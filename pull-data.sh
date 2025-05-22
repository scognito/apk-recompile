#!/bin/sh

adb shell "run-as com.ants360.yicamera.international tar -cf shared_prefs.tar shared_prefs"

adb shell "run-as com.ants360.yicamera.international mv shared_prefs.tar cache/"

adb shell "run-as com.ants360.yicamera.international cat cache/shared_prefs.tar" > shared_prefs_on_pc.tar

adb shell "run-as com.ants360.yicamera.international rm cache/shared_prefs.tar"
