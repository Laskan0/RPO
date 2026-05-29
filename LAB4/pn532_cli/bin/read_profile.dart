import 'dart:convert';

import 'package:pn532_cli/pn532_cli.dart';

void main(List<String> args) {
  final connstring = args.isNotEmpty
      ? args.first
      : 'pn532_uart:/dev/tty.usbserial-TGJLH5CH';

  print('Opening libnfc device: $connstring');
  print('Hold the card on the reader...');

  final reader = LibNfcReader(connstring: connstring);

  try {
    reader.open();

    final storedProfile = reader.readStoredProfile();

    if (storedProfile == null) {
      print('Card not found.');
      return;
    }

    print('Card UID: ${storedProfile.card.uidCompactHex}');
    print('Raw profile payload:');
    print(storedProfile.payload);

    try {
      final json = jsonDecode(storedProfile.payload);
      print('Decoded profile:');
      print(const JsonEncoder.withIndent('  ').convert(json));
    } catch (_) {
      print('Profile payload is not valid JSON.');
    }
  } finally {
    reader.close();
  }
}
