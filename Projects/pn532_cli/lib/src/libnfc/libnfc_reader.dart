// lib/src/libnfc/libnfc_reader.dart

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';

import 'package:ffi/ffi.dart';

import '../models.dart';
import 'libnfc_bindings.dart';

const List<int> mifareDefaultKey = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const List<int> mifareProfileBlocks = [4];

class LibNfcStoredProfile {
  const LibNfcStoredProfile({required this.card, required this.payload});

  final Pn532Card card;
  final String payload;
}

class LibNfcReader {
  LibNfcReader({this.connstring = 'pn532_uart:/dev/tty.usbserial-TGJLH5CH'});

  final String connstring;

  late final LibNfcBindings _nfc;
  Pointer<NfcContext> _context = nullptr;
  Pointer<NfcDevice> _device = nullptr;

  bool get isOpen => _device != nullptr;

  void open() {
    _nfc = LibNfcBindings(openLibNfc());

    final contextPtr = calloc<Pointer<NfcContext>>();

    try {
      _nfc.nfcInit(contextPtr);

      _context = contextPtr.value;

      if (_context == nullptr) {
        throw StateError('libnfc: nfc_init failed');
      }

      final connstringPtr = connstring.toNativeUtf8();

      try {
        _device = _nfc.nfcOpen(_context, connstringPtr);

        if (_device == nullptr) {
          throw StateError('libnfc: nfc_open failed for $connstring');
        }
      } finally {
        calloc.free(connstringPtr);
      }

      final initResult = _nfc.nfcInitiatorInit(_device);

      if (initResult < 0) {
        throw StateError('libnfc: nfc_initiator_init failed: ${_lastError()}');
      }
    } finally {
      calloc.free(contextPtr);
    }
  }

  void close() {
    if (_device != nullptr) {
      _nfc.nfcClose(_device);
      _device = nullptr;
    }

    if (_context != nullptr) {
      _nfc.nfcExit(_context);
      _context = nullptr;
    }
  }

  Pn532Card? scanOneCard() {
    if (_device == nullptr) {
      throw StateError('LibNfcReader is not open. Call open() first.');
    }

    final modulation = calloc<NfcModulation>();
    final target = calloc<NfcTarget>();

    try {
      modulation.ref
        ..nmt = nmtIso14443A
        ..nbr = nbr106;

      final result = _nfc.nfcInitiatorSelectPassiveTarget(
        _device,
        modulation.ref,
        nullptr,
        0,
        target,
      );

      if (result <= 0) {
        return null;
      }

      final nai = target.ref.nti.nai;

      final uidLength = nai.szUidLen;

      if (uidLength <= 0 || uidLength > 10) {
        throw StateError('libnfc: invalid UID length: $uidLength');
      }

      final uid = <int>[];

      for (var i = 0; i < uidLength; i++) {
        uid.add(nai.abtUid[i]);
      }

      final atqa = <int>[nai.abtAtqa[0], nai.abtAtqa[1]];

      return Pn532Card(uid: uid, atqa: atqa, sak: nai.btSak);
    } finally {
      calloc.free(modulation);
      calloc.free(target);
    }
  }

  String? readProfilePayload({
    List<int> blocks = mifareProfileBlocks,
    List<int> keyA = mifareDefaultKey,
  }) {
    return readStoredProfile(blocks: blocks, keyA: keyA)?.payload;
  }

  LibNfcStoredProfile? readStoredProfile({
    List<int> blocks = mifareProfileBlocks,
    List<int> keyA = mifareDefaultKey,
    Duration timeout = const Duration(seconds: 10),
    bool allowToolFallback = true,
  }) {
    final card = waitForOneCard(timeout: timeout);

    if (card == null) {
      return null;
    }

    final bytes = <int>[];

    try {
      _setEasyFraming(false);

      try {
        for (final block in blocks) {
          bytes.addAll(_readMifareClassicBlock(block, card.uid, keyA));
        }
      } finally {
        _setEasyFraming(true);
      }
    } catch (_) {
      if (!allowToolFallback) {
        rethrow;
      }

      close();
      bytes.addAll(
        _readProfileStorageWithNfcMfclassic(
          connstring: connstring,
          card: card,
          blocks: blocks,
        ),
      );
    }

    try {
      return LibNfcStoredProfile(
        card: card,
        payload: _decodeProfilePayload(bytes),
      );
    } catch (_) {
      if (!allowToolFallback) {
        rethrow;
      }

      if (isOpen) {
        close();
      }

      final fallbackBytes = _readProfileStorageWithNfcMfclassic(
        connstring: connstring,
        card: card,
        blocks: blocks,
      );

      return LibNfcStoredProfile(
        card: card,
        payload: _decodeProfilePayload(fallbackBytes),
      );
    }
  }

  Pn532Card writeProfilePayload({
    required String payload,
    List<int> blocks = mifareProfileBlocks,
    List<int> keyA = mifareDefaultKey,
    Duration timeout = const Duration(seconds: 10),
    bool allowToolFallback = true,
  }) {
    final card = waitForOneCard(timeout: timeout);

    if (card == null) {
      throw StateError('card not found before profile write');
    }

    final payloadBytes = utf8.encode(payload);
    final capacity = blocks.length * 16 - 2;

    if (payloadBytes.length > capacity) {
      throw StateError(
        'card profile is too large: ${payloadBytes.length} bytes, capacity is $capacity bytes',
      );
    }

    final storage = List<int>.filled(blocks.length * 16, 0);
    storage[0] = (payloadBytes.length >> 8) & 0xff;
    storage[1] = payloadBytes.length & 0xff;

    for (var i = 0; i < payloadBytes.length; i++) {
      storage[i + 2] = payloadBytes[i];
    }

    try {
      _setEasyFraming(false);

      try {
        for (var i = 0; i < blocks.length; i++) {
          final start = i * 16;
          final blockData = storage.sublist(start, start + 16);
          _writeMifareClassicBlock(blocks[i], blockData, card.uid, keyA);
        }
      } finally {
        _setEasyFraming(true);
      }
    } catch (e) {
      if (!allowToolFallback) {
        rethrow;
      }

      close();
      _writeProfilePayloadWithNfcMfclassic(
        connstring: connstring,
        card: card,
        storage: storage,
        blocks: blocks,
      );
    }

    return card;
  }

  Pn532Card? waitForOneCard({
    Duration timeout = const Duration(seconds: 10),
    Duration interval = const Duration(milliseconds: 200),
  }) {
    final stopwatch = Stopwatch()..start();

    while (stopwatch.elapsed < timeout) {
      final card = scanOneCard();

      if (card != null) {
        return card;
      }

      sleep(interval);
    }

    return null;
  }

  List<int> _readMifareClassicBlock(int block, List<int> uid, List<int> keyA) {
    _authenticateMifareClassicBlock(block, uid, keyA);

    final response = _transceive([0x30, block]);

    if (response.length != 16) {
      throw StateError(
        'libnfc: invalid read response for block $block: ${response.length} bytes',
      );
    }

    return response;
  }

  void _writeMifareClassicBlock(
    int block,
    List<int> data,
    List<int> uid,
    List<int> keyA,
  ) {
    if (data.length != 16) {
      throw ArgumentError.value(data.length, 'data.length', 'must be 16');
    }

    _authenticateMifareClassicBlock(block, uid, keyA);

    final writeAck = _transceive([0xa0, block]);
    _ensureMifareAck(writeAck, 'write command for block $block');

    final dataAck = _transceive(data);
    _ensureMifareAck(dataAck, 'write data for block $block');
  }

  void _authenticateMifareClassicBlock(
    int block,
    List<int> uid,
    List<int> keyA,
  ) {
    if (keyA.length != 6) {
      throw ArgumentError.value(keyA.length, 'keyA.length', 'must be 6');
    }

    if (uid.length < 4) {
      throw ArgumentError.value(uid.length, 'uid.length', 'must be at least 4');
    }

    final uidTail = uid.sublist(max(0, uid.length - 4));
    final command = <int>[0x60, block, ...keyA, ...uidTail];
    final result = _transceive(command, allowEmptyResponse: true);

    if (result.isNotEmpty && !_isMifareAck(result)) {
      throw StateError('libnfc: authentication failed for block $block');
    }
  }

  List<int> _transceive(
    List<int> data, {
    bool allowEmptyResponse = false,
    int timeoutMs = 1000,
  }) {
    if (_device == nullptr) {
      throw StateError('LibNfcReader is not open. Call open() first.');
    }

    final tx = calloc<Uint8>(data.length);
    final rx = calloc<Uint8>(264);

    try {
      for (var i = 0; i < data.length; i++) {
        tx[i] = data[i];
      }

      final result = _nfc.nfcInitiatorTransceiveBytes(
        _device,
        tx,
        data.length,
        rx,
        264,
        timeoutMs,
      );

      if (result < 0) {
        throw StateError('libnfc: transceive failed: ${_lastError()}');
      }

      if (result == 0 && !allowEmptyResponse) {
        throw StateError('libnfc: empty transceive response');
      }

      return [for (var i = 0; i < result; i++) rx[i]];
    } finally {
      calloc.free(tx);
      calloc.free(rx);
    }
  }

  void _ensureMifareAck(List<int> response, String operation) {
    if (!_isMifareAck(response)) {
      throw StateError('libnfc: MIFARE ACK not received for $operation');
    }
  }

  bool _isMifareAck(List<int> response) {
    return response.length == 1 && (response.first & 0x0f) == 0x0a;
  }

  void _setEasyFraming(bool enabled) {
    if (_device == nullptr) {
      throw StateError('LibNfcReader is not open. Call open() first.');
    }

    final result = _nfc.nfcDeviceSetPropertyBool(
      _device,
      npEasyFraming,
      enabled,
    );

    if (result < 0) {
      throw StateError(
        'libnfc: failed to ${enabled ? "enable" : "disable"} easy framing: ${_lastError()}',
      );
    }
  }

  String _lastError() {
    if (_device == nullptr) {
      return 'unknown error';
    }

    final ptr = _nfc.nfcStrError(_device);

    if (ptr == nullptr) {
      return 'unknown error';
    }

    return ptr.toDartString();
  }
}

String _decodeProfilePayload(List<int> bytes) {
  if (bytes.length < 2) {
    throw StateError('card profile storage is too small');
  }

  final payloadLength = (bytes[0] << 8) | bytes[1];
  final capacity = bytes.length - 2;

  if (payloadLength <= 0 || payloadLength > capacity) {
    throw StateError('card profile is empty or corrupted');
  }

  final payload = bytes.sublist(2, 2 + payloadLength);

  for (final byte in payload) {
    final isAllowedWhitespace = byte == 0x09 || byte == 0x0a || byte == 0x0d;
    if (byte < 0x20 && !isAllowedWhitespace) {
      throw StateError('card profile contains control bytes');
    }
  }

  return utf8.decode(payload);
}

List<int> _readProfileStorageWithNfcMfclassic({
  required String connstring,
  required Pn532Card card,
  required List<int> blocks,
}) {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  var attempt = 0;
  Object? lastError;

  while (DateTime.now().isBefore(deadline)) {
    attempt++;

    try {
      final dump = _readDumpWithNfcMfclassic(
        connstring: connstring,
        card: card,
      );
      final storage = <int>[];

      for (final block in blocks) {
        final start = block * 16;
        storage.addAll(dump.sublist(start, start + 16));
      }

      _decodeProfilePayload(storage);

      return storage;
    } catch (e) {
      lastError = e;
      sleep(const Duration(milliseconds: 350));
    }
  }

  throw StateError(
    'nfc-mfclassic profile read failed after $attempt attempts. Last error: $lastError',
  );
}

void _writeProfilePayloadWithNfcMfclassic({
  required String connstring,
  required Pn532Card card,
  required List<int> storage,
  required List<int> blocks,
}) {
  final baseDump = _readDumpWithNfcMfclassic(
    connstring: connstring,
    card: card,
  );
  final tempDir = Directory.systemTemp.createTempSync('pn532_profile_');
  final updatedDump = File('${tempDir.path}/updated.mfd');

  try {
    final originalDumpFile = File('${tempDir.path}/original.mfd')
      ..writeAsBytesSync(baseDump);
    final updated = List<int>.from(baseDump);

    for (var i = 0; i < blocks.length; i++) {
      final sourceStart = i * 16;
      final targetStart = blocks[i] * 16;

      for (var j = 0; j < 16; j++) {
        updated[targetStart + j] = storage[sourceStart + j];
      }
    }

    updatedDump.writeAsBytesSync(updated);

    final tool = _resolveNfcMfclassic();
    final uidArg = 'U${card.uidCompactHex}';
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    var attempt = 0;
    Object? lastError;

    while (DateTime.now().isBefore(deadline)) {
      attempt++;

      try {
        final write = _runNfcMfclassicWrite(
          tool: tool,
          connstring: connstring,
          args: [
            'w',
            'A',
            uidArg,
            updatedDump.path,
            originalDumpFile.path,
            'f',
          ],
        );

        if (write.exitCode != 0) {
          throw StateError(
            'nfc-mfclassic write failed for $connstring: ${write.stderr}${write.stdout}',
          );
        }

        final verifyDump = _readDumpWithNfcMfclassic(
          connstring: connstring,
          card: card,
        );

        _verifyProfileStorage(
          expectedStorage: storage,
          actualDump: verifyDump,
          blocks: blocks,
        );

        return;
      } catch (e) {
        lastError = e;
        sleep(const Duration(milliseconds: 350));
      }
    }

    throw StateError(
      'nfc-mfclassic write verification failed after $attempt attempts. Last error: $lastError',
    );
  } finally {
    try {
      tempDir.deleteSync(recursive: true);
    } catch (_) {
      // Ignore temp cleanup errors.
    }
  }
}

void _verifyProfileStorage({
  required List<int> expectedStorage,
  required List<int> actualDump,
  required List<int> blocks,
}) {
  for (var i = 0; i < blocks.length; i++) {
    final expectedStart = i * 16;
    final actualStart = blocks[i] * 16;
    final expected = expectedStorage.sublist(expectedStart, expectedStart + 16);
    final actual = actualDump.sublist(actualStart, actualStart + 16);

    if (!_sameBytes(expected, actual)) {
      throw StateError(
        'nfc-mfclassic write verification failed for block ${blocks[i]}: expected ${_hexBytes(expected)}, got ${_hexBytes(actual)}',
      );
    }
  }
}

String _hexBytes(List<int> bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(' ');
}

List<int> _readDumpWithNfcMfclassic({
  required String connstring,
  required Pn532Card card,
}) {
  final tool = _resolveNfcMfclassic();
  final tempDir = Directory.systemTemp.createTempSync('pn532_profile_');
  final originalDump = File('${tempDir.path}/original.mfd');

  try {
    final uidArg = 'U${card.uidCompactHex}';
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    var attempt = 0;
    ProcessResult? lastRead;

    while (DateTime.now().isBefore(deadline)) {
      attempt++;
      final read = Process.runSync(tool, [
        'r',
        'a',
        uidArg,
        originalDump.path,
      ], environment: _libNfcToolEnvironment(connstring));
      lastRead = read;

      if (read.exitCode == 0 && originalDump.existsSync()) {
        final dump = originalDump.readAsBytesSync();

        if (dump.length < 1024) {
          throw StateError(
            'nfc-mfclassic dump is too small: ${dump.length} bytes',
          );
        }

        return dump;
      }

      final output = '${read.stderr}${read.stdout}'.toLowerCase();
      final canRetry =
          read.exitCode == 0 ||
          output.contains('no tag was found') ||
          output.contains('tag disappeared') ||
          output.contains('error opening nfc reader');

      if (!canRetry) {
        throw StateError(
          'nfc-mfclassic read failed for $connstring: ${read.stderr}${read.stdout}',
        );
      }

      sleep(const Duration(milliseconds: 350));
    }

    throw StateError(
      'nfc-mfclassic read failed for $connstring after $attempt attempts. Keep the same card flat on the reader until the operation finishes. Last output: ${lastRead?.stderr}${lastRead?.stdout}',
    );
  } finally {
    try {
      tempDir.deleteSync(recursive: true);
    } catch (_) {
      // Ignore temp cleanup errors.
    }
  }
}

ProcessResult _runNfcMfclassicWrite({
  required String tool,
  required String connstring,
  required List<String> args,
}) {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  var attempt = 0;
  ProcessResult? lastWrite;

  while (DateTime.now().isBefore(deadline)) {
    attempt++;
    final write = Process.runSync(
      tool,
      args,
      environment: _libNfcToolEnvironment(connstring),
    );
    lastWrite = write;

    if (write.exitCode == 0) {
      return write;
    }

    final output = '${write.stderr}${write.stdout}'.toLowerCase();
    final canRetry =
        output.contains('no tag was found') ||
        output.contains('tag disappeared') ||
        output.contains('error opening nfc reader');

    if (!canRetry) {
      return write;
    }

    sleep(const Duration(milliseconds: 350));
  }

  return ProcessResult(
    lastWrite?.pid ?? 0,
    lastWrite?.exitCode ?? 1,
    lastWrite?.stdout ?? '',
    'nfc-mfclassic write failed after $attempt attempts. Keep the same card flat on the reader until the operation finishes. Last output: ${lastWrite?.stderr}${lastWrite?.stdout}',
  );
}

bool _sameBytes(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }

  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) {
      return false;
    }
  }

  return true;
}

Map<String, String> _libNfcToolEnvironment(String connstring) {
  return {
    'LIBNFC_DEFAULT_DEVICE': connstring,
    'LIBNFC_DEVICE': connstring,
    'LIBNFC_INTRUSIVE_SCAN': 'yes',
  };
}

String _resolveNfcMfclassic() {
  final candidates = <String>[
    'nfc-mfclassic',
    '/opt/homebrew/bin/nfc-mfclassic',
    '/opt/homebrew/Cellar/libnfc/1.8.0/bin/nfc-mfclassic',
    '/usr/local/bin/nfc-mfclassic',
  ];
  final failures = <String>[];

  for (final candidate in candidates) {
    late final ProcessResult result;

    try {
      result = Process.runSync(candidate, const []);
    } catch (e) {
      failures.add('$candidate: $e');
      continue;
    }

    final output = '${result.stdout}\n${result.stderr}';

    if (result.exitCode == 0 || output.contains('Usage: nfc-mfclassic')) {
      return candidate;
    }

    failures.add('$candidate: exit ${result.exitCode}; ${output.trim()}');
  }

  throw StateError(
    'nfc-mfclassic was not found or could not be executed. Tried: ${failures.join(" | ")}',
  );
}
