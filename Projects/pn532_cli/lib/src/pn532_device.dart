// lib/src/pn532_device.dart

import 'dart:async';
import 'dart:typed_data';

import 'package:libserialport/libserialport.dart';

import 'models.dart';
import 'pn532_frame.dart';
import 'utils.dart';

class Pn532Device {
  Pn532Device({required this.portName, this.debug = false});

  final String portName;
  final bool debug;

  late final SerialPort _port;
  late final SerialPortReader _reader;
  StreamSubscription<Uint8List>? _subscription;

  final List<int> _rxBuffer = [];

  Future<void> open() async {
    _port = SerialPort(portName);

    if (!_port.openReadWrite()) {
      throw StateError(
        'Cannot open port: $portName\nSerialPort error: ${SerialPort.lastError}',
      );
    }

    final config = SerialPortConfig()
      ..baudRate = 115200
      ..bits = 8
      ..stopBits = 1
      ..parity = SerialPortParity.none;

    _port.config = config;

    _reader = SerialPortReader(_port);
    _subscription = _reader.stream.listen((data) {
      _rxBuffer.addAll(data);

      if (debug) {
        print('RX: ${toHex(data)}');
      }
    });

    if (debug) {
      print('Opened port: $portName');
    }
  }

  Future<void> close() async {
    await _subscription?.cancel();

    try {
      _port.close();
      _port.dispose();
    } catch (_) {
      // Ignore close errors.
    }
  }

  Future<void> wakeUp() async {
    _rxBuffer.clear();

    final wakeup = <int>[0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00];

    if (debug) {
      print('TX wakeup: ${toHex(wakeup)}');
    }

    _port.write(Uint8List.fromList(wakeup));

    // Даем PN532 время после переподключения питания / открытия serial port.
    await sleepMs(1000);

    _rxBuffer.clear();
  }

  Future<FirmwareInfo?> getFirmwareVersion() async {
    for (var attempt = 1; attempt <= 3; attempt++) {
      if (debug) {
        print('GetFirmwareVersion attempt $attempt');
      }

      final response = await _sendCommand(
        commandData: [0x02],
        label: 'GetFirmwareVersion',
        waitMs: 1000,
      );

      final frames = parsePn532Frames(response);

      for (final body in frames) {
        // Response:
        // D5 03 IC VER REV SUPPORT
        if (body.length >= 6 && body[0] == 0xD5 && body[1] == 0x03) {
          return FirmwareInfo(
            ic: body[2],
            version: body[3],
            revision: body[4],
            support: body[5],
          );
        }
      }

      await sleepMs(500);
      await wakeUp();
    }

    return null;
  }

  Future<bool> samConfiguration() async {
    for (var attempt = 1; attempt <= 3; attempt++) {
      if (debug) {
        print('SAMConfiguration attempt $attempt');
      }

      final response = await _sendCommand(
        commandData: [0x14, 0x01, 0x14, 0x01],
        label: 'SAMConfiguration',
        waitMs: 1000,
      );

      final frames = parsePn532Frames(response);

      for (final body in frames) {
        // Response:
        // D5 15
        if (body.length >= 2 && body[0] == 0xD5 && body[1] == 0x15) {
          return true;
        }
      }

      await sleepMs(500);
      await wakeUp();
    }

    return false;
  }

  Future<Pn532Card?> pollCard() async {
    final response = await _sendCommand(
      commandData: [0x4A, 0x01, 0x00],
      label: 'InListPassiveTarget',
      waitMs: 1200,
      quiet: true,
    );

    final frames = parsePn532Frames(response);

    for (final body in frames) {
      // Response:
      // D5 4B NbTg Tg SENS_RES[2] SEL_RES NFCIDLength NFCIDData...
      if (body.length < 8) {
        continue;
      }

      if (body[0] != 0xD5 || body[1] != 0x4B) {
        continue;
      }

      final targetsCount = body[2];

      if (targetsCount == 0) {
        return null;
      }

      final atqa = body.sublist(4, 6);
      final sak = body[6];

      final uidLength = body[7];
      final uidStart = 8;
      final uidEnd = uidStart + uidLength;

      if (uidEnd > body.length) {
        return null;
      }

      final uid = body.sublist(uidStart, uidEnd);

      return Pn532Card(uid: uid, atqa: atqa, sak: sak);
    }

    return null;
  }

  Future<List<int>> _sendCommand({
    required List<int> commandData,
    required String label,
    required int waitMs,
    bool quiet = false,
  }) async {
    _rxBuffer.clear();

    final frame = buildPn532Frame(commandData);

    if (debug && !quiet) {
      print('');
      print('TX $label: ${toHex(frame)}');
    }

    final written = _port.write(Uint8List.fromList(frame));

    if (debug && !quiet) {
      print('Written: $written bytes');
    }

    await sleepMs(waitMs);

    final response = List<int>.from(_rxBuffer);

    if (debug && !quiet) {
      print('Full RX $label: ${toHex(response)}');
    }

    return response;
  }
}
