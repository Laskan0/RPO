// bin/libnfc_test.dart

import 'package:pn532_cli/pn532_cli.dart';

void main(List<String> args) {
  final connstring = args.isNotEmpty
      ? args.first
      : 'pn532_uart:/dev/tty.usbserial-TGJLH5CH';

  print('Opening libnfc device: $connstring');

  final reader = LibNfcReader(connstring: connstring);

  try {
    reader.open();

    print('libnfc reader opened.');
    print('Поднеси карту к PN532...');

    final card = reader.scanOneCard();

    if (card == null) {
      print('Card not found.');
      return;
    }

    print('Card found.');
    print('UID: ${card.uidHex}');
    print('UID compact: ${card.uidCompactHex}');
    print('ATQA: ${card.atqaHex}');
    print('SAK: ${card.sakHex}');
  } finally {
    reader.close();
  }
}
