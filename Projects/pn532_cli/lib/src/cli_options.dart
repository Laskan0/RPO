// lib/src/cli_options.dart

class CliOptions {
  CliOptions({
    required this.command,
    required this.portName,
    required this.debug,
    required this.showHelp,
  });

  final String command;
  final String? portName;
  final bool debug;
  final bool showHelp;

  factory CliOptions.parse(List<String> args) {
    var command = 'help';
    String? portName;
    var debug = false;
    var showHelp = false;
    var commandWasSet = false;

    for (var i = 0; i < args.length; i++) {
      final arg = args[i];

      if (arg == '--help' || arg == '-h') {
        showHelp = true;
        continue;
      }

      if (arg == '--debug') {
        debug = true;
        continue;
      }

      if (arg == '--port') {
        if (i + 1 >= args.length) {
          throw ArgumentError('Missing value after --port');
        }

        portName = args[i + 1];
        i++;
        continue;
      }

      if (arg.startsWith('--')) {
        throw ArgumentError('Unknown option: $arg');
      }

      if (!commandWasSet) {
        command = arg;
        commandWasSet = true;
        continue;
      }

      throw ArgumentError('Unexpected argument: $arg');
    }

    return CliOptions(
      command: command,
      portName: portName,
      debug: debug,
      showHelp: showHelp || command == 'help',
    );
  }
}
