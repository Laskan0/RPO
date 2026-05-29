// lib/src/pn532_frame.dart

List<int> buildPn532Frame(List<int> commandData) {
  // TFI 0xD4 = host to PN532.
  final body = <int>[0xD4, ...commandData];

  final len = body.length & 0xFF;
  final lcs = (-len) & 0xFF;

  final bodySum = body.fold<int>(0, (sum, byte) => (sum + byte) & 0xFF);
  final dcs = (-bodySum) & 0xFF;

  return <int>[0x00, 0x00, 0xFF, len, lcs, ...body, dcs, 0x00];
}

List<List<int>> parsePn532Frames(List<int> bytes) {
  final frames = <List<int>>[];

  for (var i = 0; i <= bytes.length - 6; i++) {
    if (bytes[i] != 0x00 || bytes[i + 1] != 0x00 || bytes[i + 2] != 0xFF) {
      continue;
    }

    final len = bytes[i + 3];
    final lcs = bytes[i + 4];

    // ACK frame:
    // 00 00 FF 00 FF 00
    if (len == 0x00 && lcs == 0xFF) {
      continue;
    }

    if (((len + lcs) & 0xFF) != 0x00) {
      continue;
    }

    final bodyStart = i + 5;
    final bodyEnd = bodyStart + len;
    final dcsIndex = bodyEnd;
    final postambleIndex = dcsIndex + 1;

    if (postambleIndex >= bytes.length) {
      continue;
    }

    final body = bytes.sublist(bodyStart, bodyEnd);
    final dcs = bytes[dcsIndex];

    final checksum =
        (body.fold<int>(0, (sum, byte) => sum + byte) + dcs) & 0xFF;

    if (checksum != 0x00) {
      continue;
    }

    frames.add(body);
  }

  return frames;
}
