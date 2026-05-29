// lib/src/models.dart

import 'utils.dart';

class FirmwareInfo {
  FirmwareInfo({
    required this.ic,
    required this.version,
    required this.revision,
    required this.support,
  });

  final int ic;
  final int version;
  final int revision;
  final int support;

  bool get isPn532 => ic == 0x32;

  String get icHex => '0x${hexByte(ic)}';

  String get firmwareVersion => '$version.$revision';

  String get supportHex => '0x${hexByte(support)}';

  @override
  String toString() {
    return 'FirmwareInfo(ic: $icHex, version: $firmwareVersion, support: $supportHex)';
  }
}

class Pn532Card {
  Pn532Card({required this.uid, required this.atqa, required this.sak});

  final List<int> uid;
  final List<int> atqa;
  final int sak;

  String get uidHex => toHex(uid);

  String get uidCompactHex => uid.map(hexByte).join();

  String get atqaHex => toHex(atqa);

  String get sakHex => '0x${hexByte(sak)}';

  bool get isMifareClassicLike {
    // SAK 0x08 is commonly seen for MIFARE Classic 1K-compatible cards.
    return sak == 0x08;
  }

  bool hasSameUid(Pn532Card other) {
    if (uid.length != other.uid.length) {
      return false;
    }

    for (var i = 0; i < uid.length; i++) {
      if (uid[i] != other.uid[i]) {
        return false;
      }
    }

    return true;
  }

  @override
  String toString() {
    return 'Pn532Card(uid: $uidHex, atqa: $atqaHex, sak: $sakHex)';
  }
}
