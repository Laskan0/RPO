// lib/src/serial_ports.dart

import 'package:libserialport/libserialport.dart';

List<String> availableSerialPorts() {
  return SerialPort.availablePorts;
}

String? findLikelySerialPort() {
  final ports = SerialPort.availablePorts;

  if (ports.isEmpty) {
    return null;
  }

  final candidates = ports.where(_isLikelyUsbSerialPort).toList();

  if (candidates.isNotEmpty) {
    candidates.sort(_comparePorts);
    return candidates.first;
  }

  final cuPorts = ports.where((port) {
    return port.startsWith('/dev/cu.') &&
        !port.toLowerCase().contains('bluetooth') &&
        !port.toLowerCase().contains('debug');
  }).toList();

  if (cuPorts.isNotEmpty) {
    cuPorts.sort();
    return cuPorts.first;
  }

  return null;
}

bool _isLikelyUsbSerialPort(String port) {
  final lower = port.toLowerCase();

  if (!port.startsWith('/dev/cu.')) {
    return false;
  }

  return lower.contains('usbserial') ||
      lower.contains('usbmodem') ||
      lower.contains('slab') ||
      lower.contains('wch') ||
      lower.contains('ch340') ||
      lower.contains('cp210');
}

int _comparePorts(String a, String b) {
  final scoreA = _portScore(a);
  final scoreB = _portScore(b);

  if (scoreA != scoreB) {
    return scoreB.compareTo(scoreA);
  }

  return a.compareTo(b);
}

int _portScore(String port) {
  final lower = port.toLowerCase();
  var score = 0;

  if (lower.contains('usbserial')) score += 100;
  if (lower.contains('slab')) score += 90;
  if (lower.contains('cp210')) score += 80;
  if (lower.contains('wch')) score += 70;
  if (lower.contains('ch340')) score += 70;
  if (lower.contains('usbmodem')) score += 50;
  if (lower.contains('bluetooth')) score -= 100;
  if (lower.contains('debug')) score -= 100;

  return score;
}
