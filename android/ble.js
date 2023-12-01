// https://reverseengineering.stackexchange.com/a/25183
// could probs just do this in javascript...
function encodeHex(byteArray) {
    const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
    const StringClass = Java.use('java.lang.String');
    const hexChars = HexClass.encodeHex(byteArray);
    return StringClass.$new(hexChars).toString();
}

Java.perform(function () {
    var bluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
    bluetoothGatt.writeCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic", "[B", "int").implementation = function (c, data, writeType) {
        const retVal = this.writeCharacteristic(c, data, writeType);
        console.log(JSON.stringify(
            {
                characteristicUUID: c.getUuid().toString(),
                serviceUUID: c.getService().getUuid().toString(),
                data: encodeHex(data),
                writeType: writeType,
                retVal: retVal,
                description: "writeCharacteristic",
                backtrace: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
            }, null, 4));
        return retVal;
    };
    const bluetoothGattCallback = Java.use("android.bluetooth.BluetoothGattCallback");
    // https://github.com/frida/frida/issues/310#issuecomment-462447292
    bluetoothGattCallback.$init.overload().implementation = function () {
        const hookCallback = Java.use(this.$className);
        let getInformation = function (gatt, characteristic, status, description) {
            return JSON.stringify({
                address: gatt.getDevice().getAddress().toString(),
                characteristicUUID: characteristic.getUuid().toString(),
                serviceUUID: characteristic.getService().getUuid().toString(),
                data: encodeHex(characteristic.getValue()),
                status: status,
                description: description,
                backtrace: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())
            }, null, 4);
        }

        hookCallback.onCharacteristicRead.implementation = function (gatt, characteristic, status) {
            const retVal = hookCallback.onCharacteristicRead.call(this, gatt, characteristic, status);
            console.log(getInformation(gatt, characteristic, status, "Characteristic read"));
            return retVal;
        };
        hookCallback.onCharacteristicWrite.implementation = function (gatt, characteristic, status) {
            const retVal = hookCallback.onCharacteristicWrite.call(this, gatt, characteristic, status);
            console.log(getInformation(gatt, characteristic, status, "Characteristic write"));
            return retVal;
        };
        hookCallback.onCharacteristicChanged.implementation = function (gatt, characteristic) {
            const retVal = hookCallback.onCharacteristicChanged.call(this, gatt, characteristic);
            console.log(getInformation(gatt, characteristic, -1, "Characteristic change"));
            return retVal;
        };
        return this.$init();
    };
});

