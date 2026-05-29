// bin/pn532_cli.dart

import 'dart:io';

import 'package:pn532_cli/pn532_cli.dart';

Future<void> main(List<String> args) async {
  late final CliOptions options;

  try {
    options = CliOptions.parse(args);
  } on ArgumentError catch (error) {
    stderr.writeln(error.message ?? error.toString());
    printHelp();
    exitCode = 64;
    return;
  }

  if (options.showHelp) {
    printHelp();
    return;
  }

  if (options.command == 'list-ports') {
    listPorts();
    return;
  }

  final portName = options.portName ?? findLikelySerialPort();

  if (portName == null) {
    stderr.writeln('No suitable USB serial port found.');
    stderr.writeln('');
    listPorts();
    stderr.writeln('');
    stderr.writeln('Use --port manually, for example:');
    stderr.writeln(
      '  dart run bin/pn532_cli.dart scan --port /dev/cu.usbserial-XXXX',
    );
    exitCode = 1;
    return;
  }

  if (options.portName == null) {
    print('Using serial port: $portName');
  }

  final device = Pn532Device(portName: portName, debug: options.debug);

  try {
    await device.open();
    await device.wakeUp();

    switch (options.command) {
      case 'firmware':
        await runFirmware(device);
        break;

      case 'scan':
        await runScan(device);
        break;

      case 'poll':
        await runPoll(device);
        break;

      default:
        stderr.writeln('Unknown command: ${options.command}');
        printHelp();
        exitCode = 64;
    }
  } on StateError catch (error) {
    stderr.writeln(error.message);
    exitCode = 1;
  } finally {
    await device.close();
  }
}
