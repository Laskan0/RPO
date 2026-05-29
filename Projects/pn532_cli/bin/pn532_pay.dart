import 'dart:async';
import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> args) async {
  final port = optionValue(args, '--port', '/dev/cu.usbserial-TGJLH5CH');
  final apiBase = trimRightSlash(
    optionValue(args, '--api', 'https://localhost:8888/api/v1'),
  );
  final terminalSerial = optionValue(args, '--terminal', 'TERM-001');
  final username = optionValue(args, '--username', 'admin');
  final password = optionValue(args, '--password', 'admin123');
  final amountText = optionValue(args, '--amount', '65');
  final tokenArg = nullableOptionValue(args, '--token');

  final amount = int.tryParse(amountText);
  if (amount == null || amount <= 0) {
    stderr.writeln('Invalid --amount. Example: --amount 65');
    exit(2);
  }

  stdout.writeln('Scanning card on port: $port');
  final scanOutput = await runPn532Scan(port);

  final cardNumber = extractUidCompact(scanOutput);
  stdout.writeln('Card UID compact: $cardNumber');

  final client = HttpClient()
    ..badCertificateCallback = (certificate, host, port) {
      return host == 'localhost' || host == '127.0.0.1';
    };

  try {
    final token =
        tokenArg ??
        await loginAndGetToken(
          client: client,
          apiBase: apiBase,
          username: username,
          password: password,
        );

    final result = await authorizePayment(
      client: client,
      apiBase: apiBase,
      token: token,
      terminalSerial: terminalSerial,
      cardNumber: cardNumber,
      amount: amount,
    );

    stdout.writeln('');
    stdout.writeln('Payment response:');
    stdout.writeln(const JsonEncoder.withIndent('  ').convert(result));

    final approved = result['approved'] == true;
    stdout.writeln('');
    stdout.writeln(approved ? 'APPROVED' : 'DECLINED');
  } finally {
    client.close(force: true);
  }
}

String optionValue(List<String> args, String name, String defaultValue) {
  final index = args.indexOf(name);
  if (index == -1) {
    return defaultValue;
  }

  if (index + 1 >= args.length) {
    throw ArgumentError('Missing value for $name');
  }

  return args[index + 1];
}

String? nullableOptionValue(List<String> args, String name) {
  final index = args.indexOf(name);
  if (index == -1) {
    return null;
  }

  if (index + 1 >= args.length) {
    throw ArgumentError('Missing value for $name');
  }

  return args[index + 1];
}

String trimRightSlash(String value) {
  var result = value;
  while (result.endsWith('/')) {
    result = result.substring(0, result.length - 1);
  }
  return result;
}

Future<String> runPn532Scan(String port) async {
  final process = await Process.start('dart', [
    'run',
    'bin/pn532_cli.dart',
    'scan',
    '--port',
    port,
  ], runInShell: true);

  final buffer = StringBuffer();

  process.stdout.transform(utf8.decoder).listen((chunk) {
    stdout.write(chunk);
    buffer.write(chunk);
  });

  process.stderr.transform(utf8.decoder).listen((chunk) {
    stderr.write(chunk);
    buffer.write(chunk);
  });

  final exitCode = await process.exitCode.timeout(
    const Duration(seconds: 40),
    onTimeout: () {
      process.kill();
      throw TimeoutException(
        'PN532 scan timeout. Try bringing the card closer to the reader.',
      );
    },
  );

  final output = buffer.toString();

  if (exitCode != 0) {
    throw Exception('PN532 scan failed with exit code $exitCode');
  }

  return output;
}

String extractUidCompact(String output) {
  final allLines = const LineSplitter().convert(output);

  final preferredLines = allLines.where((line) {
    final lower = line.toLowerCase();
    return lower.contains('uid') ||
        lower.contains('card') ||
        lower.contains('карта');
  }).toList();

  final groups = <List<String>>[
    preferredLines.reversed.toList(),
    allLines.reversed.toList(),
  ];

  for (final lines in groups) {
    for (final line in lines) {
      final compact = RegExp(r'\b[0-9a-fA-F]{8,20}\b')
          .allMatches(line)
          .map((match) => match.group(0)!)
          .where((value) => value.length.isEven)
          .toList();

      if (compact.isNotEmpty) {
        return compact.last.toLowerCase();
      }

      final bytes = RegExp(
        r'\b[0-9a-fA-F]{2}\b',
      ).allMatches(line).map((match) => match.group(0)!).toList();

      if (bytes.length >= 4 && bytes.length <= 10) {
        return bytes.join().toLowerCase();
      }
    }
  }

  throw FormatException('Cannot extract UID from PN532 scan output:\n$output');
}

Future<String> loginAndGetToken({
  required HttpClient client,
  required String apiBase,
  required String username,
  required String password,
}) async {
  final response = await postJson(
    client: client,
    uri: Uri.parse('$apiBase/auth/login'),
    body: {'username': username, 'password': password},
  );

  final token = response['token'];
  if (token is! String || token.isEmpty) {
    throw Exception('Login response does not contain token: $response');
  }

  return token;
}

Future<Map<String, dynamic>> authorizePayment({
  required HttpClient client,
  required String apiBase,
  required String token,
  required String terminalSerial,
  required String cardNumber,
  required int amount,
}) async {
  return postJson(
    client: client,
    uri: Uri.parse('$apiBase/terminal/transactions/authorize'),
    token: token,
    body: {
      'terminal_serial': terminalSerial,
      'card_number': cardNumber,
      'amount': amount,
    },
  );
}

Future<Map<String, dynamic>> postJson({
  required HttpClient client,
  required Uri uri,
  required Map<String, dynamic> body,
  String? token,
}) async {
  final request = await client.postUrl(uri);

  request.headers.contentType = ContentType.json;
  request.headers.set(HttpHeaders.acceptHeader, 'application/json');

  if (token != null) {
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
  }

  request.write(jsonEncode(body));

  final response = await request.close();
  final responseBody = await utf8.decodeStream(response);

  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw HttpException(
      'HTTP ${response.statusCode} from $uri\n$responseBody',
      uri: uri,
    );
  }

  final decoded = jsonDecode(responseBody);

  if (decoded is! Map) {
    throw FormatException('Expected JSON object, got: $responseBody');
  }

  return Map<String, dynamic>.from(decoded);
}
