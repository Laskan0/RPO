// lib/src/pn532_controller.dart

import 'dart:async';

import 'models.dart';
import 'pn532_device.dart';
import 'utils.dart';

class Pn532Controller {
  Pn532Controller({required this.device});

  final Pn532Device device;

  FirmwareInfo? _firmware;
  bool _initialized = false;

  FirmwareInfo? get firmware => _firmware;

  bool get isInitialized => _initialized;

  Future<bool> initialize() async {
    final firmware = await device.getFirmwareVersion();

    if (firmware == null) {
      _initialized = false;
      return false;
    }

    _firmware = firmware;

    final samOk = await device.samConfiguration();

    if (!samOk) {
      _initialized = false;
      return false;
    }

    _initialized = true;
    return true;
  }

  Future<Pn532Card?> scanOneCard({
    Duration timeout = const Duration(seconds: 15),
    Duration interval = const Duration(milliseconds: 300),
  }) async {
    _ensureInitialized();

    final deadline = DateTime.now().add(timeout);

    while (DateTime.now().isBefore(deadline)) {
      final card = await device.pollCard();

      if (card != null) {
        return card;
      }

      await Future<void>.delayed(interval);
    }

    return null;
  }

  Stream<Pn532Card> watchCards({
    Duration interval = const Duration(milliseconds: 700),
    bool emitSameCardRepeatedly = false,
  }) async* {
    _ensureInitialized();

    String? lastUid;

    while (true) {
      final card = await device.pollCard();

      if (card == null) {
        lastUid = null;
        await sleepMs(interval.inMilliseconds);
        continue;
      }

      final uid = card.uidHex;

      if (emitSameCardRepeatedly || uid != lastUid) {
        lastUid = uid;
        yield card;
      }

      await sleepMs(interval.inMilliseconds);
    }
  }

  void _ensureInitialized() {
    if (!_initialized) {
      throw StateError(
        'Pn532Controller is not initialized. Call initialize() first.',
      );
    }
  }
}
