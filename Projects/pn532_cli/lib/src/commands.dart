// lib/src/commands.dart

import 'dart:async';
import 'dart:io';

import 'package:libserialport/libserialport.dart';

import 'pn532_controller.dart';
import 'pn532_device.dart';

void listPorts() {
  final ports = SerialPort.availablePorts;

  if (ports.isEmpty) {
    print('Serial ports not found.');
    return;
  }

  print('Available serial ports:');
  for (final port in ports) {
    print('- $port');
  }
}

Future<void> runFirmware(Pn532Device device) async {
  final firmware = await device.getFirmwareVersion();

  if (firmware == null) {
    print('PN532 firmware response not found.');
    return;
  }

  print('PN532 detected.');
  print('IC: ${firmware.icHex} ${firmware.isPn532 ? "(PN532)" : ""}');
  print('Firmware version: ${firmware.firmwareVersion}');
  print('Support byte: ${firmware.supportHex}');
}

Future<Pn532Controller?> initializeController(Pn532Device device) async {
  final controller = Pn532Controller(device: device);

  final initialized = await controller.initialize();

  if (!initialized) {
    print('PN532 initialization failed.');
    return null;
  }

  final firmware = controller.firmware;

  if (firmware != null) {
    print('PN532 detected: firmware ${firmware.firmwareVersion}');
  }

  print('PN532 is ready.');

  return controller;
}

Future<void> runScan(Pn532Device device) async {
  final controller = await initializeController(device);

  if (controller == null) {
    return;
  }

  print('Поднеси карту к антенне PN532.');
  print('Ожидание карты...');
  print('');

  final card = await controller.scanOneCard(
    timeout: const Duration(seconds: 30),
  );

  if (card == null) {
    print('');
    print('Card not found before timeout.');
    return;
  }

  print('');
  print('Card found.');
  print('UID: ${card.uidHex}');
  print('UID compact: ${card.uidCompactHex}');
  print('ATQA: ${card.atqaHex}');
  print('SAK: ${card.sakHex}');
}

Future<void> runPoll(Pn532Device device) async {
  final controller = await initializeController(device);

  if (controller == null) {
    return;
  }

  print('Поднеси карту к антенне PN532.');
  print('Для выхода нажми Ctrl + C.');
  print('');

  var dotsTimer = Timer.periodic(const Duration(milliseconds: 800), (_) {
    stdout.write('.');
  });

  try {
    await for (final card in controller.watchCards()) {
      dotsTimer.cancel();

      print('');
      print('Card found.');
      print('UID: ${card.uidHex}');
      print('UID compact: ${card.uidCompactHex}');
      print('ATQA: ${card.atqaHex}');
      print('SAK: ${card.sakHex}');
      print('');

      dotsTimer = Timer.periodic(const Duration(milliseconds: 800), (_) {
        stdout.write('.');
      });
    }
  } finally {
    dotsTimer.cancel();
  }
}

void printHelp() {
  print('''
PN532 CLI

Usage:
  dart run bin/pn532_cli.dart list-ports
  dart run bin/pn532_cli.dart firmware
  dart run bin/pn532_cli.dart scan
  dart run bin/pn532_cli.dart poll

Commands:
  list-ports    Show available serial ports
  firmware      Read PN532 firmware version
  scan          Wait for one NFC card, print UID, then exit
  poll          Continuously watch NFC cards

Options:
  --port <path>    Serial port path.
                   If omitted, the app tries to auto-detect USB serial port.

  --debug          Print raw TX/RX frames

Examples:
  dart run bin/pn532_cli.dart list-ports
  dart run bin/pn532_cli.dart firmware
  dart run bin/pn532_cli.dart scan
  dart run bin/pn532_cli.dart poll
  dart run bin/pn532_cli.dart poll --debug
  dart run bin/pn532_cli.dart scan --port /dev/cu.usbserial-TGJLH5CH
''');
}
