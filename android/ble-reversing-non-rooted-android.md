I wrote the following program for the [M5StickC](https://shop.m5stack.com/products/stick-c) to control [two Govee lights](https://www.amazon.co.uk/dp/B0C3VRT5TS?th=1), using traffic snooped using [ble.js](./android/ble.js):

```cpp
#include <M5StickC.h>

#include "BLEDevice.h"

// This program simply controls on/off for Govee lights

static BLEUUID serviceUUID("00010203-0405-0607-0809-0a0b0c0d1910");
static BLEUUID charUUID("00010203-0405-0607-0809-0a0b0c0d2b11");
static uint8_t on_value[] = {0x33, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x33};
static uint8_t off_value[] = {0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x32};

static std::vector<BLEAddress> bulbAddresses = {
    BLEAddress("60:74:F4:67:B9:1F"), BLEAddress("60:74:F4:64:78:43")};

class Bulb {
 public:
  explicit Bulb(BLEAddress address) : m_address(address) {}

  bool On() { return action(true); }
  bool Off() { return action(false); }

 private:
  bool action(bool on) {
    auto client = std::unique_ptr<BLEClient>(BLEDevice::createClient());
    if (!client) {
      return false;
    }

    // Connect to the remove BLE Server.
    if (!client->connect(m_address)) {
      return false;
    }

    auto remoteService = client->getService(serviceUUID);
    if (remoteService == nullptr) {
      return false;
    }

    auto remoteCharacteristic = remoteService->getCharacteristic(charUUID);
    if (remoteCharacteristic == nullptr) {
      return false;
    }
    auto value = on ? on_value : off_value;
    remoteCharacteristic->writeValue(value, sizeof(on_value));
    client->disconnect();
    return true;
  }

  BLEAddress m_address;
};

void setup() {
  M5.begin();
  const auto vbat = M5.Axp.GetVbatData() * 1.1 / 1000;
  M5.Lcd.printf("vbat:%.3fV\r\n", vbat);
  BLEDevice::init("");
}

const unsigned int loopDelay = 1000;  // 1 second
const unsigned int initLoopsUntilPowerDown = 10;
static unsigned int loopsUntilPowerDown = initLoopsUntilPowerDown;

void loop() {
  if (loopsUntilPowerDown-- == 0) {
    M5.Axp.PowerOff();
    return;
  }
  M5.update();

  const bool on = M5.BtnA.wasPressed();
  const bool off = M5.BtnB.wasPressed();

  if (on || off) {
    loopsUntilPowerDown = initLoopsUntilPowerDown;
    for (const auto& bulbAddress : bulbAddresses) {
      auto bulb = std::unique_ptr<Bulb>(new Bulb(bulbAddress));
      const auto res = on ? bulb->On() : bulb->Off();
      if (!res) {
        // try again
        on ? bulb->On() : bulb->Off();
      }
    }
  }

  delay(loopDelay);
}

```

To use the Frida script, I installed the Govee app on a [Moto E13](https://www.amazon.co.uk/dp/B0BVZSWMHG) (non-rooted) with developer mode enabled. I extracted the apks for the Govee app by
1. getting the paths for the apks using adb: ```adb shell pm path com.govee.com```
2. pulling the individual apks using ```adb pull``` using the path from step 1. above.

I then injected the [Frida Gadget](https://frida.re/docs/gadget/) into ```base.apk``` using the docker container of [this](https://github.com/ksg97031/frida-gadget).
Then I combined the altered ```base.apk``` with the other two apks with [APK Editor](https://github.com/REAndroid/APKEditor) to avoid the misery of trying to get multi-part installs to work after modifying ```base.apk```. After deleting the vanilla Govee app from the device, I installed the doctored version with
```adb install -r combined.apk```.

By running

```frida -l ble.js -U Gadget``` after starting the Govee app, I could see the BLE traffic for switching lights on and off (among other things).
