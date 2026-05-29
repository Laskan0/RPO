import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter/material.dart';
import 'package:http/io_client.dart';
import 'package:pn532_cli/pn532_cli.dart';

const String cardProfileSecret = 'transport-terminal-profile-v1';

void main() {
  runApp(const TransportTerminalApp());
}

class TransportTerminalApp extends StatelessWidget {
  const TransportTerminalApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Transport Terminal',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFFC62828),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFFFF5F5),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF9F1D20),
          foregroundColor: Color(0xFF4A1012),
          centerTitle: true,
          elevation: 0,
          titleTextStyle: TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.w700,
          ),
        ),
        cardTheme: const CardThemeData(
          color: Color(0xFFFFFBFB),
          surfaceTintColor: Color(0xFFFFE4E4),
          elevation: 0,
          margin: EdgeInsets.zero,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.all(Radius.circular(14)),
            side: BorderSide(color: Color(0xFFF0C9C9)),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFFFFFFFF),
          labelStyle: const TextStyle(color: Color(0xFFA12A2D)),
          helperStyle: const TextStyle(color: Color(0xFF7E5A5B)),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Color(0xFFD98989)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(10),
            borderSide: const BorderSide(color: Color(0xFFC62828), width: 2),
          ),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            backgroundColor: const Color(0xFFC62828),
            foregroundColor: Colors.white,
            disabledBackgroundColor: const Color(0xFFE7B8B8),
            disabledForegroundColor: const Color(0xFFFFF4F4),
            minimumSize: const Size.fromHeight(48),
            textStyle: const TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w700,
            ),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
        ),
        switchTheme: SwitchThemeData(
          thumbColor: WidgetStateProperty.resolveWith((states) {
            if (states.contains(WidgetState.selected)) {
              return const Color(0xFFFFFFFF);
            }
            return const Color(0xFF8A6F70);
          }),
          trackColor: WidgetStateProperty.resolveWith((states) {
            if (states.contains(WidgetState.selected)) {
              return const Color(0xFFD04444);
            }
            return const Color(0xFFF0DADA);
          }),
        ),
        useMaterial3: true,
      ),
      home: const PaymentPage(),
    );
  }
}

class LibNfcScanResult {
  const LibNfcScanResult({
    required this.found,
    this.uidHex,
    this.uidCompactHex,
    this.atqaHex,
    this.sakHex,
    this.message,
    this.error,
  });

  final bool found;
  final String? uidHex;
  final String? uidCompactHex;
  final String? atqaHex;
  final String? sakHex;
  final String? message;
  final String? error;

  factory LibNfcScanResult.fromMap(Map<dynamic, dynamic> map) {
    return LibNfcScanResult(
      found: map['found'] == true,
      uidHex: map['uidHex'] as String?,
      uidCompactHex: map['uidCompactHex'] as String?,
      atqaHex: map['atqaHex'] as String?,
      sakHex: map['sakHex'] as String?,
      message: map['message'] as String?,
      error: map['error'] as String?,
    );
  }
}

class LibNfcProfileResult {
  const LibNfcProfileResult({
    required this.found,
    this.uidCompactHex,
    this.payload,
    this.error,
  });

  final bool found;
  final String? uidCompactHex;
  final String? payload;
  final String? error;

  factory LibNfcProfileResult.fromMap(Map<dynamic, dynamic> map) {
    return LibNfcProfileResult(
      found: map['found'] == true,
      uidCompactHex: map['uidCompactHex'] as String?,
      payload: map['payload'] as String?,
      error: map['error'] as String?,
    );
  }
}

class CardProfile {
  const CardProfile({required this.ownerName, required this.balance});

  final String ownerName;
  final int balance;

  Map<String, dynamic> toSignedJson() {
    return {'v': 1, 'ow': ownerName, 'balance': balance};
  }

  Map<String, dynamic> toUnsignedJson() {
    return toSignedJson();
  }

  factory CardProfile.fromJson(Map<String, dynamic> json) {
    return CardProfile(
      ownerName: (json['ow'] as String?) ?? '',
      balance: (json['balance'] as num?)?.toInt() ?? 0,
    );
  }
}

String buildCardProfilePayload({
  required String ownerName,
  required int balance,
}) {
  final payload = '$balance|$ownerName';
  final payloadBytes = utf8.encode(payload);

  if (payloadBytes.length > 14) {
    throw Exception(
      'Card data is too large for one MIFARE block. Use a shorter owner name.',
    );
  }

  return payload;
}

CardProfile parseAndVerifyCardProfile(String payload) {
  final separatorIndex = payload.indexOf('|');

  if (separatorIndex <= 0 || separatorIndex == payload.length - 1) {
    throw Exception('Card profile is invalid');
  }

  final balance = int.tryParse(payload.substring(0, separatorIndex));
  final ownerName = payload.substring(separatorIndex + 1).trim();

  if (balance == null || balance < 0) {
    throw Exception('Card balance is invalid');
  }

  if (ownerName.isEmpty) {
    throw Exception('Card owner name is empty');
  }

  return CardProfile(ownerName: ownerName, balance: balance);
}

String signCardProfile(Map<String, dynamic> payload) {
  final canonicalPayload = jsonEncode(payload);
  final bytes = utf8.encode('$canonicalPayload|$cardProfileSecret');
  var hash = 0xcbf29ce484222325;

  for (final byte in bytes) {
    hash ^= byte;
    hash = (hash * 0x100000001b3) & 0xffffffffffffffff;
  }

  return hash.toRadixString(16).padLeft(16, '0');
}

void libNfcScanIsolateEntry(List<dynamic> args) {
  final sendPort = args[0] as SendPort;
  final connstring = args[1] as String;
  final timeoutSeconds = args[2] as int;

  final reader = LibNfcReader(connstring: connstring);
  final stopwatch = Stopwatch()..start();

  try {
    reader.open();

    while (stopwatch.elapsed < Duration(seconds: timeoutSeconds)) {
      final card = reader.scanOneCard();

      if (card != null) {
        sendPort.send({
          'found': true,
          'uidHex': card.uidHex,
          'uidCompactHex': card.uidCompactHex,
          'atqaHex': card.atqaHex,
          'sakHex': card.sakHex,
        });
        return;
      }

      sleep(const Duration(milliseconds: 200));
    }

    sendPort.send({
      'found': false,
      'message': 'Card not found before timeout.',
    });
  } catch (e) {
    sendPort.send({'found': false, 'error': e.toString()});
  } finally {
    try {
      reader.close();
    } catch (_) {
      // Ignore close errors.
    }
  }
}

void libNfcProfileIsolateEntry(List<dynamic> args) {
  final sendPort = args[0] as SendPort;
  final connstring = args[1] as String;
  final mode = args[2] as String;
  final payload = args.length > 3 ? args[3] as String? : null;

  final reader = LibNfcReader(connstring: connstring);

  try {
    reader.open();

    if (mode == 'write') {
      if (payload == null || payload.isEmpty) {
        throw Exception('profile payload is required');
      }

      final card = reader.writeProfilePayload(payload: payload);
      sendPort.send({
        'found': true,
        'uidCompactHex': card.uidCompactHex,
        'payload': payload,
      });
      return;
    }

    if (mode == 'read') {
      final storedProfile = reader.readStoredProfile();

      if (storedProfile == null) {
        sendPort.send({'found': false});
        return;
      }

      sendPort.send({
        'found': true,
        'uidCompactHex': storedProfile.card.uidCompactHex,
        'payload': storedProfile.payload,
      });
      return;
    }

    throw Exception('unknown profile mode: $mode');
  } catch (e) {
    sendPort.send({'found': false, 'error': e.toString()});
  } finally {
    try {
      reader.close();
    } catch (_) {
      // Ignore close errors.
    }
  }
}

Future<LibNfcScanResult> runLibNfcScanInIsolate({
  required String connstring,
  required int timeoutSeconds,
}) async {
  final receivePort = ReceivePort();

  await Isolate.spawn(libNfcScanIsolateEntry, [
    receivePort.sendPort,
    connstring,
    timeoutSeconds,
  ]);

  final message = await receivePort.first;
  receivePort.close();

  if (message is Map) {
    return LibNfcScanResult.fromMap(message);
  }

  return LibNfcScanResult(
    found: false,
    error: 'Unexpected isolate response: $message',
  );
}

Future<LibNfcProfileResult> runLibNfcProfileInIsolate({
  required String connstring,
  required String mode,
  String? payload,
}) async {
  final receivePort = ReceivePort();

  await Isolate.spawn(libNfcProfileIsolateEntry, [
    receivePort.sendPort,
    connstring,
    mode,
    payload,
  ]);

  final message = await receivePort.first;
  receivePort.close();

  if (message is Map) {
    return LibNfcProfileResult.fromMap(message);
  }

  return LibNfcProfileResult(
    found: false,
    error: 'Unexpected isolate response: $message',
  );
}

class PaymentPage extends StatefulWidget {
  const PaymentPage({super.key});

  @override
  State<PaymentPage> createState() => _PaymentPageState();
}

class SectionCard extends StatelessWidget {
  const SectionCard({
    super.key,
    required this.title,
    required this.icon,
    required this.children,
  });

  final String title;
  final IconData icon;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: const Color(0xFFFFE1E1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(icon, color: const Color(0xFFB4262A)),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.w800,
                      color: Color(0xFF2B1718),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),
            ...children,
          ],
        ),
      ),
    );
  }
}

class _PaymentPageState extends State<PaymentPage> {
  final apiBaseController = TextEditingController(
    text: 'https://localhost:8888/api/v1',
  );

  final terminalController = TextEditingController(text: 'TERM-1001');
  final cardController = TextEditingController(text: 'b754105e');
  final amountController = TextEditingController(text: '65');

  final ownerNameController = TextEditingController(text: 'Test Passenger');
  final tariffController = TextEditingController(text: 'regular');
  final expiresAtController = TextEditingController(text: '2026-12-31');
  final initialBalanceController = TextEditingController(text: '500');
  final keyIdController = TextEditingController(text: '1');

  final connstringController = TextEditingController(
    text: 'pn532_uart:/dev/tty.usbserial-TGJLH5CH',
  );

  bool loadingPayment = false;
  bool loadingCreateCard = false;
  bool loadingCardInfo = false;
  bool scanning = false;
  bool isBlocked = false;

  String paymentResultText = '';
  String createCardResultText = '';
  String cardInfoText = '';
  String scanResultText = '';

  bool? approved;

  late final IOClient client;

  @override
  void initState() {
    super.initState();

    final httpClient = HttpClient()
      ..badCertificateCallback = (certificate, host, port) {
        return host == 'localhost' || host == '127.0.0.1';
      };

    client = IOClient(httpClient);
  }

  @override
  void dispose() {
    apiBaseController.dispose();
    terminalController.dispose();
    cardController.dispose();
    amountController.dispose();
    ownerNameController.dispose();
    tariffController.dispose();
    expiresAtController.dispose();
    initialBalanceController.dispose();
    keyIdController.dispose();
    connstringController.dispose();
    client.close();
    super.dispose();
  }

  Future<void> scanCard() async {
    setState(() {
      scanning = true;
      scanResultText = 'Opening libnfc reader...\nWaiting for card...';
      approved = null;
    });

    try {
      final connstring = connstringController.text.trim();

      if (connstring.isEmpty) {
        throw Exception('libnfc connstring is required');
      }

      final result = await runLibNfcScanInIsolate(
        connstring: connstring,
        timeoutSeconds: 10,
      );

      if (!mounted) {
        return;
      }

      if (result.error != null) {
        setState(() {
          scanResultText = 'Scan error: ${result.error}';
        });
        return;
      }

      if (!result.found) {
        setState(() {
          scanResultText =
              '''
Card not found.

Timeout: 10 seconds
${result.message ?? ''}
''';
        });
        return;
      }

      final uidCompact = result.uidCompactHex;

      if (uidCompact == null || uidCompact.isEmpty) {
        throw Exception('libnfc returned empty UID compact');
      }

      setState(() {
        cardController.text = uidCompact;
        scanResultText =
            '''
Card found via libnfc.

UID: ${result.uidHex}
UID compact: ${result.uidCompactHex}
ATQA: ${result.atqaHex}
SAK: ${result.sakHex}
''';
      });
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() {
        scanResultText = 'Scan error: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          scanning = false;
        });
      }
    }
  }

  Future<void> createCard() async {
    setState(() {
      loadingCreateCard = true;
      createCardResultText = '';
    });

    try {
      final apiBase = trimRightSlash(apiBaseController.text.trim());
      final cardNumber = cardController.text.trim().toLowerCase();
      final ownerName = ownerNameController.text.trim();
      final initialBalance = int.tryParse(initialBalanceController.text.trim());
      final keyId = int.tryParse(keyIdController.text.trim());

      if (apiBase.isEmpty) {
        throw Exception('API base URL is required');
      }

      if (connstringController.text.trim().isEmpty) {
        throw Exception('libnfc connstring is required');
      }

      if (cardNumber.isEmpty) {
        throw Exception('Card UID is required. Scan card first.');
      }

      if (ownerName.isEmpty) {
        throw Exception('Owner name is required');
      }

      if (initialBalance == null || initialBalance < 0) {
        throw Exception('Initial balance must be zero or positive integer');
      }

      if (keyId == null || keyId <= 0) {
        throw Exception('Key ID must be positive integer');
      }

      final profilePayload = buildCardProfilePayload(
        ownerName: ownerName,
        balance: initialBalance,
      );

      setState(() {
        createCardResultText =
            'Writing balance and owner name to physical card...';
      });

      final profileWriteResult = await runLibNfcProfileInIsolate(
        connstring: connstringController.text.trim(),
        mode: 'write',
        payload: profilePayload,
      );

      if (profileWriteResult.error != null) {
        throw Exception(
          'Card profile write failed: ${profileWriteResult.error}',
        );
      }

      if (!profileWriteResult.found) {
        throw Exception(
          'Card not found while writing profile. Keep the same card on the reader until writing finishes.',
        );
      }

      if ((profileWriteResult.uidCompactHex ?? '').toLowerCase() !=
          cardNumber) {
        throw Exception(
          'Different card presented. Expected $cardNumber, got ${profileWriteResult.uidCompactHex}',
        );
      }

      final token = await login(apiBase);

      final response = await client.post(
        Uri.parse('$apiBase/cards'),
        headers: {
          HttpHeaders.authorizationHeader: 'Bearer $token',
          HttpHeaders.contentTypeHeader: 'application/json',
          HttpHeaders.acceptHeader: 'application/json',
        },
        body: jsonEncode({
          'card_number': cardNumber,
          'owner_name': ownerName,
          'balance': initialBalance,
          'is_blocked': isBlocked,
          'key_id': keyId,
        }),
      );

      final body = response.body;

      if (response.statusCode == 409) {
        setState(() {
          createCardResultText =
              'Card already exists.\n\nBackend response:\n$body';
        });
        return;
      }

      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw Exception('HTTP ${response.statusCode}: $body');
      }

      final json = jsonDecode(body) as Map<String, dynamic>;

      setState(() {
        createCardResultText =
            'Card data written and backend card created successfully:\n\n${const JsonEncoder.withIndent('  ').convert(json)}\n\nCard data stored on physical card:\n$profilePayload';
      });
    } catch (e) {
      setState(() {
        createCardResultText = 'Create card error: $e';
      });
    } finally {
      setState(() {
        loadingCreateCard = false;
      });
    }
  }

  Future<void> readCardInfo() async {
    setState(() {
      loadingCardInfo = true;
      cardInfoText = 'Reading UID, balance and owner name from card...';
      approved = null;
    });

    try {
      final connstring = connstringController.text.trim();

      if (connstring.isEmpty) {
        throw Exception('libnfc connstring is required');
      }

      final profileReadResult = await runLibNfcProfileInIsolate(
        connstring: connstring,
        mode: 'read',
      );

      if (!mounted) {
        return;
      }

      if (profileReadResult.error != null) {
        throw Exception(profileReadResult.error);
      }

      if (!profileReadResult.found || profileReadResult.payload == null) {
        throw Exception('Card info not found. Keep the card on the reader.');
      }

      final profile = parseAndVerifyCardProfile(profileReadResult.payload!);
      final uid = profileReadResult.uidCompactHex?.toLowerCase();

      if (uid == null || uid.isEmpty) {
        throw Exception('Physical card UID was not read');
      }

      setState(() {
        cardController.text = uid;
        ownerNameController.text = profile.ownerName;
        initialBalanceController.text = profile.balance.toString();
        cardInfoText =
            '''
Card info read from physical card.

UID: $uid
Owner name: ${profile.ownerName}
Balance: ${profile.balance}
Raw card data: ${profileReadResult.payload}
''';
      });
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() {
        cardInfoText = 'Read card info error: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          loadingCardInfo = false;
        });
      }
    }
  }

  Future<void> authorizePayment() async {
    setState(() {
      loadingPayment = true;
      paymentResultText = '';
      approved = null;
    });

    try {
      final apiBase = trimRightSlash(apiBaseController.text.trim());
      final terminalSerial = terminalController.text.trim();
      final amount = int.tryParse(amountController.text.trim());

      if (apiBase.isEmpty) {
        throw Exception('API base URL is required');
      }

      if (connstringController.text.trim().isEmpty) {
        throw Exception('libnfc connstring is required');
      }

      if (terminalSerial.isEmpty) {
        throw Exception('Terminal serial is required');
      }

      if (amount == null || amount <= 0) {
        throw Exception('Amount must be a positive integer');
      }

      setState(() {
        paymentResultText =
            'Reading balance and owner name from physical card...';
      });

      final profileReadResult = await runLibNfcProfileInIsolate(
        connstring: connstringController.text.trim(),
        mode: 'read',
      );

      if (profileReadResult.error != null) {
        throw Exception('Card profile read failed: ${profileReadResult.error}');
      }

      if (!profileReadResult.found || profileReadResult.payload == null) {
        throw Exception(
          'Card profile not found. Keep the registered card on the reader and try again.',
        );
      }

      final profile = parseAndVerifyCardProfile(profileReadResult.payload!);
      final physicalCardNumber = profileReadResult.uidCompactHex?.toLowerCase();

      if (physicalCardNumber == null || physicalCardNumber.isEmpty) {
        throw Exception('Physical card UID was not read');
      }

      final cardNumber = physicalCardNumber;

      setState(() {
        cardController.text = cardNumber;
        ownerNameController.text = profile.ownerName;
        initialBalanceController.text = profile.balance.toString();
        paymentResultText =
            'Card data read for ${profile.ownerName}, balance ${profile.balance}. Authorizing payment...';
      });

      final token = await login(apiBase);

      final response = await client.post(
        Uri.parse('$apiBase/terminal/authorize'),
        headers: {
          HttpHeaders.authorizationHeader: 'Bearer $token',
          HttpHeaders.contentTypeHeader: 'application/json',
          HttpHeaders.acceptHeader: 'application/json',
        },
        body: jsonEncode({
          'terminal_serial_number': terminalSerial,
          'card_number': cardNumber,
          'amount': amount,
        }),
      );

      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw Exception('HTTP ${response.statusCode}: ${response.body}');
      }

      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final authorized = json['authorized'] == true;
      final updatedBalance = authorized
          ? profile.balance - amount
          : profile.balance;
      var cardUpdateText = 'Card balance was not changed.';

      if (authorized) {
        if (updatedBalance < 0) {
          throw Exception(
            'Backend authorized payment, but physical card balance would become negative.',
          );
        }

        setState(() {
          paymentResultText =
              'Payment authorized. Writing new card balance $updatedBalance...';
        });

        final updatedPayload = buildCardProfilePayload(
          ownerName: profile.ownerName,
          balance: updatedBalance,
        );

        final profileWriteResult = await runLibNfcProfileInIsolate(
          connstring: connstringController.text.trim(),
          mode: 'write',
          payload: updatedPayload,
        );

        if (profileWriteResult.error != null) {
          throw Exception(
            'Payment was authorized, but card balance update failed: ${profileWriteResult.error}',
          );
        }

        if (!profileWriteResult.found) {
          throw Exception(
            'Payment was authorized, but card was not found while updating balance.',
          );
        }

        final writtenUid = profileWriteResult.uidCompactHex?.toLowerCase();

        if (writtenUid != cardNumber) {
          throw Exception(
            'Payment was authorized, but a different card was presented while updating balance. Expected $cardNumber, got $writtenUid',
          );
        }

        initialBalanceController.text = updatedBalance.toString();
        cardUpdateText = 'Physical card balance updated to $updatedBalance.';
      }

      setState(() {
        approved = authorized;
        paymentResultText =
            '''
Verified card data:
${const JsonEncoder.withIndent('  ').convert(profile.toSignedJson())}

$cardUpdateText

Backend payment response:
${const JsonEncoder.withIndent('  ').convert(json)}
''';
      });
    } catch (e) {
      setState(() {
        approved = false;
        paymentResultText = 'Error: $e';
      });
    } finally {
      setState(() {
        loadingPayment = false;
      });
    }
  }

  Future<String> login(String apiBase) async {
    final response = await client.post(
      Uri.parse('$apiBase/login'),
      headers: {
        HttpHeaders.contentTypeHeader: 'application/json',
        HttpHeaders.acceptHeader: 'application/json',
      },
      body: jsonEncode({'login': 'flutter_terminal', 'password': 'password'}),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception(
        'Login failed: HTTP ${response.statusCode}: ${response.body}',
      );
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final token = json['token'];

    if (token is! String || token.isEmpty) {
      throw Exception('Login response does not contain token');
    }

    return token;
  }

  String trimRightSlash(String value) {
    var result = value;
    while (result.endsWith('/')) {
      result = result.substring(0, result.length - 1);
    }
    return result;
  }

  @override
  Widget build(BuildContext context) {
    final statusColor = approved == true
        ? const Color(0xFFC62828)
        : approved == false
        ? const Color(0xFF8E1B1F)
        : const Color(0xFF8A6F70);

    final statusText = approved == true
        ? 'APPROVED'
        : approved == false
        ? 'DECLINED / ERROR'
        : 'READY';

    return Scaffold(
      appBar: AppBar(title: const Text('Transport Terminal')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900),
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: const Color(0xFF9F1D20),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 48,
                      height: 48,
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: const Icon(
                        Icons.confirmation_number_outlined,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(width: 14),
                    const Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Transport Terminal',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 24,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          SizedBox(height: 4),
                          Text(
                            'PN532 scanner and payment authorization',
                            style: TextStyle(color: Color(0xFFFFD1D1)),
                          ),
                        ],
                      ),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 14,
                        vertical: 8,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(999),
                      ),
                      child: Text(
                        statusText,
                        style: TextStyle(
                          color: statusColor,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),
              SectionCard(
                title: 'PN532 card scanner via libnfc',
                icon: Icons.nfc_outlined,
                children: [
                  TextField(
                    controller: connstringController,
                    decoration: const InputDecoration(
                      labelText: 'libnfc connstring',
                      helperText:
                          'Example: pn532_uart:/dev/tty.usbserial-TGJLH5CH',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 20),
                  FilledButton.icon(
                    onPressed: loadingCardInfo ? null : readCardInfo,
                    icon: const Icon(Icons.badge_outlined),
                    label: loadingCardInfo
                        ? const Text('Reading card info...')
                        : const Text('Read card info'),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: scanning ? null : scanCard,
                    icon: const Icon(Icons.document_scanner_outlined),
                    label: scanning
                        ? const Text('Scanning via libnfc...')
                        : const Text('Scan card via libnfc'),
                  ),
                  const SizedBox(height: 12),
                  SelectableText(
                    scanResultText.isEmpty ? 'No scan yet.' : scanResultText,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 12),
                  SelectableText(
                    cardInfoText.isEmpty
                        ? 'No card info read yet.'
                        : cardInfoText,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              SectionCard(
                title: 'Register scanned card',
                icon: Icons.badge_outlined,
                children: [
                  TextField(
                    controller: cardController,
                    decoration: const InputDecoration(
                      labelText: 'Card UID compact',
                      helperText: 'Filled automatically after libnfc scan',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: ownerNameController,
                    decoration: const InputDecoration(
                      labelText: 'Owner name',
                      helperText: 'Stored on the physical card with balance',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: initialBalanceController,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'Initial balance',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: keyIdController,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'MIFARE key ID',
                      helperText: 'Default demo key is usually 1',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Blocked card'),
                    subtitle: const Text('Usually disabled for new cards'),
                    value: isBlocked,
                    onChanged: (value) {
                      setState(() {
                        isBlocked = value;
                      });
                    },
                  ),
                  const SizedBox(height: 20),
                  FilledButton.icon(
                    onPressed: loadingCreateCard ? null : createCard,
                    icon: const Icon(Icons.add_card_outlined),
                    label: loadingCreateCard
                        ? const Text('Adding card...')
                        : const Text('Add scanned card'),
                  ),
                  const SizedBox(height: 12),
                  SelectableText(
                    createCardResultText.isEmpty
                        ? 'No card registration yet.'
                        : createCardResultText,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              SectionCard(
                title: 'Payment authorization',
                icon: Icons.payments_outlined,
                children: [
                  TextField(
                    controller: apiBaseController,
                    decoration: const InputDecoration(
                      labelText: 'API base URL',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: terminalController,
                    decoration: const InputDecoration(
                      labelText: 'Terminal serial',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: amountController,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'Payment amount',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 20),
                  FilledButton.icon(
                    onPressed: loadingPayment ? null : authorizePayment,
                    icon: const Icon(Icons.verified_outlined),
                    label: loadingPayment
                        ? const Text('Processing...')
                        : const Text('Authorize payment'),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: const Color(0xFFFFFFFF),
                  border: Border.all(color: const Color(0xFFF0C9C9)),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.receipt_long_outlined, color: statusColor),
                        const SizedBox(width: 10),
                        Text(
                          statusText,
                          style: TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.w800,
                            color: statusColor,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    SelectableText(
                      paymentResultText.isEmpty
                          ? 'No payment yet.'
                          : paymentResultText,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 14,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }
}
