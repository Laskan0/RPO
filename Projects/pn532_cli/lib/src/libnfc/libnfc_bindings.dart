// lib/src/libnfc/libnfc_bindings.dart

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const int nmtIso14443A = 1; // тип модуляции ISO14443A
const int nbr106 = 1; // скорость 106 kbit/s
const int npEasyFraming = 11;

DynamicLibrary openLibNfc() {
  if (Platform.isMacOS) {
    final candidates = <String>[
      'libnfc.dylib',
      '/usr/local/opt/libnfc/lib/libnfc.dylib',
      '/opt/homebrew/opt/libnfc/lib/libnfc.dylib',
    ];

    for (final path in candidates) {
      try {
        return DynamicLibrary.open(path);
      } catch (_) {
        // Try next candidate.
      }
    }

    throw StateError(
      'Cannot load libnfc.dylib. Install it with: brew install libnfc',
    );
  }

  if (Platform.isLinux) {
    return DynamicLibrary.open('libnfc.so');
  }

  throw UnsupportedError('libnfc FFI is not configured for this platform.');
}

final class NfcContext extends Opaque {}

final class NfcDevice extends Opaque {}

@Packed(1)
final class NfcModulation extends Struct {
  @Int32()
  external int nmt;

  @Int32()
  external int nbr;
}

// Mirrors libnfc:
//
// typedef struct {
//   uint8_t abtAtqa[2];
//   uint8_t btSak;
//   size_t szUidLen;
//   uint8_t abtUid[10];
//   size_t szAtsLen;
//   uint8_t abtAts[254];
// } nfc_iso14443a_info;
//
// libnfc declares these structures under #pragma pack(1).
@Packed(1)
final class NfcIso14443aInfo extends Struct {
  @Array(2)
  external Array<Uint8> abtAtqa;

  @Uint8()
  external int btSak;

  @Size()
  external int szUidLen;

  @Array(10)
  external Array<Uint8> abtUid;

  @Size()
  external int szAtsLen;

  @Array(254)
  external Array<Uint8> abtAts;
}

// typedef union {
//   nfc_iso14443a_info nai;
//   ...
// } nfc_target_info;
@Packed(1)
final class NfcTargetInfo extends Union {
  external NfcIso14443aInfo nai;

  // Must be large enough to cover all libnfc target union variants.
  @Array(512)
  external Array<Uint8> raw;
}

// typedef struct {
//   nfc_target_info nti;
//   nfc_modulation nm;
// } nfc_target;
@Packed(1)
final class NfcTarget extends Struct {
  external NfcTargetInfo nti;

  external NfcModulation nm;
}

typedef NfcInitNative = Void Function(Pointer<Pointer<NfcContext>>);
typedef NfcInitDart = void Function(Pointer<Pointer<NfcContext>>);

typedef NfcExitNative = Void Function(Pointer<NfcContext>);
typedef NfcExitDart = void Function(Pointer<NfcContext>);

typedef NfcOpenNative =
    Pointer<NfcDevice> Function(Pointer<NfcContext>, Pointer<Utf8>);
typedef NfcOpenDart =
    Pointer<NfcDevice> Function(Pointer<NfcContext>, Pointer<Utf8>);

typedef NfcCloseNative = Void Function(Pointer<NfcDevice>);
typedef NfcCloseDart = void Function(Pointer<NfcDevice>);

typedef NfcInitiatorInitNative = Int32 Function(Pointer<NfcDevice>);
typedef NfcInitiatorInitDart = int Function(Pointer<NfcDevice>);

typedef NfcInitiatorSelectPassiveTargetNative =
    Int32 Function(
      Pointer<NfcDevice>,
      NfcModulation,
      Pointer<Uint8>,
      Size,
      Pointer<NfcTarget>,
    );
typedef NfcInitiatorSelectPassiveTargetDart =
    int Function(
      Pointer<NfcDevice>,
      NfcModulation,
      Pointer<Uint8>,
      int,
      Pointer<NfcTarget>,
    );

typedef NfcStrErrorNative = Pointer<Utf8> Function(Pointer<NfcDevice>);
typedef NfcStrErrorDart = Pointer<Utf8> Function(Pointer<NfcDevice>);

typedef NfcDeviceSetPropertyBoolNative =
    Int32 Function(Pointer<NfcDevice>, Int32, Bool);
typedef NfcDeviceSetPropertyBoolDart =
    int Function(Pointer<NfcDevice>, int, bool);

typedef NfcInitiatorTransceiveBytesNative =
    Int32 Function(
      Pointer<NfcDevice>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Int32,
    );
typedef NfcInitiatorTransceiveBytesDart =
    int Function(
      Pointer<NfcDevice>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      int,
    );

class LibNfcBindings {
  LibNfcBindings(DynamicLibrary dylib)
    : nfcInit = dylib.lookupFunction<NfcInitNative, NfcInitDart>('nfc_init'),
      nfcExit = dylib.lookupFunction<NfcExitNative, NfcExitDart>('nfc_exit'),
      nfcOpen = dylib.lookupFunction<NfcOpenNative, NfcOpenDart>('nfc_open'),
      nfcClose = dylib.lookupFunction<NfcCloseNative, NfcCloseDart>(
        'nfc_close',
      ),
      nfcInitiatorInit = dylib
          .lookupFunction<NfcInitiatorInitNative, NfcInitiatorInitDart>(
            'nfc_initiator_init',
          ),
      nfcInitiatorSelectPassiveTarget = dylib
          .lookupFunction<
            NfcInitiatorSelectPassiveTargetNative,
            NfcInitiatorSelectPassiveTargetDart
          >('nfc_initiator_select_passive_target'),
      nfcInitiatorTransceiveBytes = dylib
          .lookupFunction<
            NfcInitiatorTransceiveBytesNative,
            NfcInitiatorTransceiveBytesDart
          >('nfc_initiator_transceive_bytes'),
      nfcDeviceSetPropertyBool = dylib
          .lookupFunction<
            NfcDeviceSetPropertyBoolNative,
            NfcDeviceSetPropertyBoolDart
          >('nfc_device_set_property_bool'),
      nfcStrError = dylib.lookupFunction<NfcStrErrorNative, NfcStrErrorDart>(
        'nfc_strerror',
      );

  final NfcInitDart nfcInit;
  final NfcExitDart nfcExit;
  final NfcOpenDart nfcOpen;
  final NfcCloseDart nfcClose;
  final NfcInitiatorInitDart nfcInitiatorInit;
  final NfcInitiatorSelectPassiveTargetDart nfcInitiatorSelectPassiveTarget;
  final NfcInitiatorTransceiveBytesDart nfcInitiatorTransceiveBytes;
  final NfcDeviceSetPropertyBoolDart nfcDeviceSetPropertyBool;
  final NfcStrErrorDart nfcStrError;
}
