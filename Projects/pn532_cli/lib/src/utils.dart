// lib/src/utils.dart

Future<void> sleepMs(int ms) {
  return Future<void>.delayed(Duration(milliseconds: ms));
}

String toHex(List<int> bytes) {
  if (bytes.isEmpty) {
    return '';
  }

  return bytes.map(hexByte).join(' ');
}

String hexByte(int byte) {
  return byte.toRadixString(16).padLeft(2, '0');
}
