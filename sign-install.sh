#!/bin/sh

cd unknown/base

# pack
apktool b -o ../base-modified.apk

cd ..

# Sign
java -jar $HOME/jar/uber-apk-signer-1.3.0.jar --allowResign --apk *.apk

mkdir signed 2> /dev/null

mv *Signed* signed

# Install
adb install-multiple signed/base-modified-aligned-debugSigned.apk signed/split_config*.apk  

# Launch
adb shell am start -S -n com.ants360.yicamera.international/com.ants360.yicamera.activity.SplashActivity

sleep 3

# Log
adb logcat --pid=$(adb shell pidof -s com.ants360.yicamera.international)
